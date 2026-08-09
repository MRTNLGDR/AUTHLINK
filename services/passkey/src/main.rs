use authlink_passkey::{
    NewPasskeyCredential, PasskeyCredentialMetadata, PasskeyCredentialRecord, PasskeyRepository,
    PasskeyStoreError, PASSKEY_CHALLENGE_BYTES, PASSKEY_CHALLENGE_TTL_SECONDS,
};
use authlink_policy::{OpenFgaClient, PolicyCheck};
use authlink_store::{AuthlinkStore, SessionRecord, StoreError};
use axum::{
    extract::State,
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, COOKIE},
        HeaderMap, HeaderValue, Method, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{env, net::SocketAddr};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;

const SESSION_COOKIE: &str = "authlink_session";

#[derive(Clone)]
struct AppState {
    repo: PasskeyRepository,
    policy: Option<OpenFgaClient>,
    policy_dev_bypass: bool,
    verifier: VerifierClient,
    rp_id: String,
    rp_name: String,
    origin: String,
}

#[derive(Clone)]
struct VerifierClient {
    base_url: String,
    http: reqwest::Client,
}

impl VerifierClient {
    fn new(base_url: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            http: reqwest::Client::new(),
        }
    }

    async fn health(&self) -> Result<Value, String> {
        let response = self
            .http
            .get(format!("{}/health", self.base_url))
            .send()
            .await
            .map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            return Err(format!("verifier health HTTP {}", response.status()));
        }
        response.json().await.map_err(|error| error.to_string())
    }

    async fn post<T: Serialize + ?Sized, U: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<U, String> {
        let response = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .json(body)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(format!("verifier HTTP {status}: {text}"));
        }
        response.json().await.map_err(|error| error.to_string())
    }
}

#[derive(Debug, Serialize)]
struct Health<'a> {
    status: &'a str,
    service: &'a str,
}

#[derive(Debug, Serialize)]
struct RuntimeStatus<'a> {
    database: &'a str,
    authorization: &'a str,
    verifier: &'a str,
    rp_id: &'a str,
    origin: &'a str,
    user_verification: &'a str,
    assurance: &'a str,
}

#[derive(Debug, Serialize)]
struct CeremonyOptionsResponse {
    challenge_id: Uuid,
    expires_in_seconds: i64,
    options: Value,
}

#[derive(Debug, Deserialize)]
struct CeremonyVerifyRequest {
    challenge_id: Uuid,
    response: Value,
}

#[derive(Debug, Serialize)]
struct CredentialResponse {
    id: Uuid,
    credential_id: String,
    credential_device_type: String,
    credential_backed_up: bool,
    transports: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CredentialListResponse {
    credentials: Vec<CredentialResponse>,
}

#[derive(Debug, Deserialize)]
struct RevokeCredentialRequest {
    credential_id: String,
}

#[derive(Debug, Serialize)]
struct AssertionSuccess {
    verified: bool,
    credential_id: String,
    auth_strength: &'static str,
    user_verified: bool,
    credential_device_type: String,
    credential_backed_up: bool,
}

#[derive(Debug, Deserialize)]
struct RegistrationVerification {
    verified: bool,
    credential: Option<VerifiedCredential>,
    aaguid: Option<String>,
    attestation_format: Option<String>,
    user_verified: Option<bool>,
    credential_device_type: Option<String>,
    credential_backed_up: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct AuthenticationVerification {
    verified: bool,
    new_counter: u64,
    credential_id: String,
    user_verified: bool,
    credential_device_type: String,
    credential_backed_up: bool,
}

#[derive(Debug, Deserialize)]
struct VerifiedCredential {
    id: String,
    public_key_b64: String,
    counter: u64,
    transports: Vec<String>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    let environment = env::var("AUTHLINK_ENV").unwrap_or_else(|_| "development".into());
    let is_production = environment.eq_ignore_ascii_case("production");
    let database_url = env::var("DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .expect("DATABASE_URL is mandatory for AuthLink Passkey");
    let store = AuthlinkStore::connect(&database_url)
        .await
        .expect("AuthLink Passkey could not connect to PostgreSQL");
    let repo = PasskeyRepository::new(store);

    let policy = OpenFgaClient::from_env().expect("valid OpenFGA configuration");
    let policy_dev_bypass = !is_production
        && env::var("AUTHLINK_POLICY_DEV_BYPASS")
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false);
    if policy.is_none() && !policy_dev_bypass {
        panic!("OpenFGA is mandatory for AuthLink Passkey; development bypass must be explicit");
    }

    let verifier = VerifierClient::new(
        env::var("AUTHLINK_WEBAUTHN_VERIFIER_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8791".into()),
    );
    verifier
        .health()
        .await
        .expect("AuthLink WebAuthn verifier must be reachable before Passkey service starts");

    let rp_id = env::var("AUTHLINK_WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".into());
    let origin = env::var("AUTHLINK_WEBAUTHN_ORIGIN").unwrap_or_else(|_| "http://localhost:5173".into());
    let rp_name = env::var("AUTHLINK_WEBAUTHN_RP_NAME").unwrap_or_else(|_| "AuthLink".into());
    if rp_id.trim().is_empty() || origin.trim().is_empty() || rp_name.trim().is_empty() {
        panic!("WebAuthn RP configuration cannot be empty");
    }

    let web_url = env::var("AUTHLINK_WEB_URL")
        .unwrap_or_else(|_| "http://localhost:5173".into())
        .trim_end_matches('/')
        .to_owned();
    let allowed_origin = HeaderValue::from_str(&web_url)
        .expect("AUTHLINK_WEB_URL must be a valid HTTP origin");
    let cors = CorsLayer::new()
        .allow_origin(allowed_origin)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([CONTENT_TYPE, AUTHORIZATION])
        .allow_credentials(true);

    let state = AppState {
        repo,
        policy,
        policy_dev_bypass,
        verifier,
        rp_id,
        rp_name,
        origin,
    };

    let app = Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/authlink/passkeys/status", get(runtime_status))
        .route("/api/v1/authlink/passkeys/credentials", get(list_credentials))
        .route("/api/v1/authlink/passkeys/registration/options", post(registration_options))
        .route("/api/v1/authlink/passkeys/registration/verify", post(registration_verify))
        .route("/api/v1/authlink/passkeys/authentication/options", post(authentication_options))
        .route("/api/v1/authlink/passkeys/authentication/verify", post(authentication_verify))
        .route("/api/v1/authlink/passkeys/credentials/revoke", post(revoke_credential))
        .fallback(not_found)
        .with_state(state)
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = env::var("AUTHLINK_PASSKEY_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8790".into())
        .parse()
        .expect("valid AUTHLINK_PASSKEY_ADDR");
    tracing::info!(%addr, %environment, "AuthLink Passkey listening");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind AuthLink Passkey");
    axum::serve(listener, app).await.expect("serve AuthLink Passkey");
}

async fn health() -> Json<Health<'static>> {
    Json(Health {
        status: "ok",
        service: "authlink-passkey",
    })
}

async fn runtime_status(State(state): State<AppState>) -> Json<RuntimeStatus<'static>> {
    Json(RuntimeStatus {
        database: "postgres",
        authorization: if state.policy.is_some() { "openfga" } else { "development-bypass" },
        verifier: "simplewebauthn-13.3.2-stateless",
        rp_id: Box::leak(state.rp_id.clone().into_boxed_str()),
        origin: Box::leak(state.origin.clone().into_boxed_str()),
        user_verification: "required",
        assurance: "webauthn-assertion",
    })
}

async fn list_credentials(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let session = match authorize(&state, &headers, "can_read").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match state.repo.list_credentials(session.tenant_id, session.identity_id).await {
        Ok(credentials) => no_store(Json(CredentialListResponse {
            credentials: credentials.into_iter().map(metadata_response).collect(),
        })
        .into_response()),
        Err(error) => passkey_store_error("PASSKEY_LIST_FAILED", error),
    }
}

async fn registration_options(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let session = match authorize(&state, &headers, "can_manage").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let credentials = match state.repo.list_credentials(session.tenant_id, session.identity_id).await {
        Ok(value) => value,
        Err(error) => return passkey_store_error("PASSKEY_LIST_FAILED", error),
    };
    let (challenge_id, challenge_b64) = match issue_challenge(&state, &session, "register").await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let user_display_name = session
        .display_name
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "AuthLink User".into());
    let body = json!({
        "challenge_b64": challenge_b64,
        "user_id_b64": URL_SAFE_NO_PAD.encode(session.identity_id.as_bytes()),
        "user_name": session.identity_id.to_string(),
        "user_display_name": user_display_name.chars().take(128).collect::<String>(),
        "rp_name": state.rp_name,
        "rp_id": state.rp_id,
        "exclude_credentials": credential_descriptors(&credentials),
    });
    match state.verifier.post::<_, Value>("/registration/options", &body).await {
        Ok(options) => no_store(Json(CeremonyOptionsResponse {
            challenge_id,
            expires_in_seconds: PASSKEY_CHALLENGE_TTL_SECONDS,
            options,
        })
        .into_response()),
        Err(error) => verifier_error("PASSKEY_OPTIONS_FAILED", error),
    }
}

async fn registration_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CeremonyVerifyRequest>,
) -> Response {
    let session = match authorize(&state, &headers, "can_manage").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let challenge = match consume_challenge(&state, &session, request.challenge_id, "register").await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let body = json!({
        "response": request.response,
        "expected_challenge": URL_SAFE_NO_PAD.encode(challenge),
        "expected_origin": state.origin,
        "expected_rp_id": state.rp_id,
    });
    let verification: RegistrationVerification = match state.verifier.post("/registration/verify", &body).await {
        Ok(value) => value,
        Err(error) => return verifier_error("PASSKEY_REGISTRATION_REJECTED", error),
    };
    if !verification.verified || verification.user_verified != Some(true) {
        return api_error(StatusCode::UNAUTHORIZED, "PASSKEY_REGISTRATION_NOT_VERIFIED");
    }
    let Some(credential) = verification.credential else {
        return internal_error("PASSKEY_REGISTRATION_MISSING_CREDENTIAL");
    };
    let public_key = match URL_SAFE_NO_PAD.decode(&credential.public_key_b64) {
        Ok(value) if !value.is_empty() => value,
        _ => return internal_error("PASSKEY_PUBLIC_KEY_INVALID"),
    };
    let counter = match u32::try_from(credential.counter) {
        Ok(value) => value,
        Err(_) => return internal_error("PASSKEY_COUNTER_OUT_OF_RANGE"),
    };
    let device_type = verification
        .credential_device_type
        .unwrap_or_else(|| "unknown".into());
    let backed_up = verification.credential_backed_up.unwrap_or(false);
    let id = Uuid::now_v7();
    let new_credential = NewPasskeyCredential {
        id,
        tenant_id: session.tenant_id,
        identity_id: session.identity_id,
        credential_id: &credential.id,
        public_key: &public_key,
        counter,
        transports: &credential.transports,
        aaguid: verification.aaguid.as_deref(),
        attestation_format: verification.attestation_format.as_deref(),
        credential_device_type: &device_type,
        credential_backed_up: backed_up,
    };
    if let Err(error) = state.repo.insert_credential(new_credential).await {
        return passkey_store_error("PASSKEY_CREDENTIAL_WRITE_FAILED", error);
    }
    no_store((
        StatusCode::CREATED,
        Json(CredentialResponse {
            id,
            credential_id: credential.id,
            credential_device_type: device_type,
            credential_backed_up: backed_up,
            transports: credential.transports,
        }),
    )
        .into_response())
}

async fn authentication_options(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let session = match authorize(&state, &headers, "can_read").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let credentials = match state.repo.list_credentials(session.tenant_id, session.identity_id).await {
        Ok(value) if value.is_empty() => return api_error(StatusCode::CONFLICT, "PASSKEY_NOT_REGISTERED"),
        Ok(value) => value,
        Err(error) => return passkey_store_error("PASSKEY_LIST_FAILED", error),
    };
    let (challenge_id, challenge_b64) = match issue_challenge(&state, &session, "authenticate").await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let body = json!({
        "challenge_b64": challenge_b64,
        "rp_id": state.rp_id,
        "allow_credentials": credential_descriptors(&credentials),
    });
    match state.verifier.post::<_, Value>("/authentication/options", &body).await {
        Ok(options) => no_store(Json(CeremonyOptionsResponse {
            challenge_id,
            expires_in_seconds: PASSKEY_CHALLENGE_TTL_SECONDS,
            options,
        })
        .into_response()),
        Err(error) => verifier_error("PASSKEY_OPTIONS_FAILED", error),
    }
}

async fn authentication_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CeremonyVerifyRequest>,
) -> Response {
    let session = match authorize(&state, &headers, "can_read").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let credential_id = match request.response.get("id").and_then(Value::as_str) {
        Some(value) if !value.is_empty() => value.to_owned(),
        _ => return api_error(StatusCode::UNPROCESSABLE_ENTITY, "PASSKEY_RESPONSE_ID_MISSING"),
    };
    let credential = match state
        .repo
        .load_credential(session.tenant_id, session.identity_id, &credential_id)
        .await
    {
        Ok(Some(value)) => value,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "PASSKEY_CREDENTIAL_NOT_FOUND"),
        Err(error) => return passkey_store_error("PASSKEY_CREDENTIAL_LOAD_FAILED", error),
    };
    let challenge = match consume_challenge(&state, &session, request.challenge_id, "authenticate").await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let body = json!({
        "response": request.response,
        "expected_challenge": URL_SAFE_NO_PAD.encode(challenge),
        "expected_origin": state.origin,
        "expected_rp_id": state.rp_id,
        "credential": verifier_credential(&credential),
    });
    let verification: AuthenticationVerification = match state.verifier.post("/authentication/verify", &body).await {
        Ok(value) => value,
        Err(error) => return verifier_error("PASSKEY_ASSERTION_REJECTED", error),
    };
    if !verification.verified || !verification.user_verified || verification.credential_id != credential.credential_id {
        return api_error(StatusCode::UNAUTHORIZED, "PASSKEY_ASSERTION_NOT_VERIFIED");
    }
    let new_counter = match u32::try_from(verification.new_counter) {
        Ok(value) => value,
        Err(_) => return internal_error("PASSKEY_COUNTER_OUT_OF_RANGE"),
    };
    match state
        .repo
        .update_counter(
            session.tenant_id,
            session.identity_id,
            &credential.credential_id,
            credential.counter,
            new_counter,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => return api_error(StatusCode::CONFLICT, "PASSKEY_COUNTER_STATE_CHANGED"),
        Err(error) => return passkey_store_error("PASSKEY_COUNTER_WRITE_FAILED", error),
    }
    if let Err(error) = state
        .repo
        .mark_session_passkey_verified(
            session.id,
            session.tenant_id,
            session.identity_id,
            &credential.credential_id,
            &verification.credential_device_type,
            verification.credential_backed_up,
        )
        .await
    {
        return passkey_store_error("PASSKEY_SESSION_ASSURANCE_FAILED", error);
    }
    let auth_strength = if session.trusted_device_id.is_some() {
        "passkey+device-possession"
    } else {
        "passkey"
    };
    no_store(Json(AssertionSuccess {
        verified: true,
        credential_id: credential.credential_id,
        auth_strength,
        user_verified: true,
        credential_device_type: verification.credential_device_type,
        credential_backed_up: verification.credential_backed_up,
    })
    .into_response())
}

async fn revoke_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RevokeCredentialRequest>,
) -> Response {
    let session = match authorize(&state, &headers, "can_manage").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if request.credential_id.is_empty() || request.credential_id.len() > 2048 {
        return api_error(StatusCode::UNPROCESSABLE_ENTITY, "PASSKEY_CREDENTIAL_ID_INVALID");
    }
    match state
        .repo
        .revoke_credential(session.tenant_id, session.identity_id, &request.credential_id)
        .await
    {
        Ok(true) => no_store(Json(json!({ "credential_id": request.credential_id, "state": "revoked" })).into_response()),
        Ok(false) => api_error(StatusCode::NOT_FOUND, "PASSKEY_CREDENTIAL_NOT_FOUND"),
        Err(error) => passkey_store_error("PASSKEY_REVOKE_FAILED", error),
    }
}

async fn issue_challenge(
    state: &AppState,
    session: &SessionRecord,
    action: &str,
) -> Result<(Uuid, String), Response> {
    let mut challenge = [0_u8; PASSKEY_CHALLENGE_BYTES];
    if let Err(error) = getrandom::fill(&mut challenge) {
        tracing::error!(error = %error, "passkey challenge entropy failed");
        return Err(internal_error("PASSKEY_ENTROPY_FAILED"));
    }
    let challenge_id = Uuid::now_v7();
    if let Err(error) = state
        .repo
        .create_challenge(
            challenge_id,
            session.tenant_id,
            session.identity_id,
            session.id,
            action,
            &challenge,
            PASSKEY_CHALLENGE_TTL_SECONDS,
        )
        .await
    {
        return Err(passkey_store_error("PASSKEY_CHALLENGE_WRITE_FAILED", error));
    }
    Ok((challenge_id, URL_SAFE_NO_PAD.encode(challenge)))
}

async fn consume_challenge(
    state: &AppState,
    session: &SessionRecord,
    challenge_id: Uuid,
    action: &str,
) -> Result<Vec<u8>, Response> {
    match state
        .repo
        .consume_challenge(
            challenge_id,
            session.tenant_id,
            session.identity_id,
            session.id,
            action,
        )
        .await
    {
        Ok(Some(record)) if record.challenge.len() == PASSKEY_CHALLENGE_BYTES => Ok(record.challenge),
        Ok(_) => Err(api_error(StatusCode::CONFLICT, "PASSKEY_CHALLENGE_INVALID_OR_EXPIRED")),
        Err(error) => Err(passkey_store_error("PASSKEY_CHALLENGE_CONSUME_FAILED", error)),
    }
}

async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    relation: &str,
) -> Result<SessionRecord, Response> {
    let session_id = session_id_from_headers(headers).ok_or_else(unauthorized)?;
    let session = match state.repo.authlink_store().load_active_session(session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => return Err(unauthorized()),
        Err(error) => return Err(store_error("SESSION_LOAD_FAILED", error)),
    };
    if let Some(policy) = &state.policy {
        let check = PolicyCheck {
            user: format!("user:{}", session.identity_id),
            relation: relation.to_owned(),
            object: format!("identity:{}", session.identity_id),
        };
        return match policy.check(&check).await {
            Ok(decision) if decision.allowed => Ok(session),
            Ok(_) => Err(api_error(StatusCode::FORBIDDEN, "PASSKEY_PERMISSION_DENIED")),
            Err(error) => Err(policy_error("POLICY_UPSTREAM_FAILED", error)),
        };
    }
    if state.policy_dev_bypass {
        return Ok(session);
    }
    Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "POLICY_UNAVAILABLE"))
}

fn credential_descriptors(credentials: &[PasskeyCredentialMetadata]) -> Vec<Value> {
    credentials
        .iter()
        .map(|credential| json!({
            "id": credential.credential_id,
            "transports": credential.transports,
        }))
        .collect()
}

fn verifier_credential(credential: &PasskeyCredentialRecord) -> Value {
    json!({
        "id": credential.credential_id,
        "public_key_b64": URL_SAFE_NO_PAD.encode(&credential.public_key),
        "counter": credential.counter,
        "transports": credential.transports,
    })
}

fn metadata_response(credential: PasskeyCredentialMetadata) -> CredentialResponse {
    CredentialResponse {
        id: credential.id,
        credential_id: credential.credential_id,
        credential_device_type: credential.credential_device_type,
        credential_backed_up: credential.credential_backed_up,
        transports: credential.transports,
    }
}

fn session_id_from_headers(headers: &HeaderMap) -> Option<Uuid> {
    let cookie = headers.get(COOKIE)?.to_str().ok()?;
    cookie
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(name, value)| {
            (name == SESSION_COOKIE)
                .then(|| Uuid::parse_str(value).ok())
                .flatten()
        })
}

fn unauthorized() -> Response {
    api_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_REQUIRED")
}

fn api_error(status: StatusCode, code: &str) -> Response {
    no_store((status, Json(json!({ "error": code }))).into_response())
}

fn internal_error(code: &str) -> Response {
    let correlation_id = Uuid::now_v7();
    tracing::error!(%correlation_id, error_code = code, "passkey internal failure");
    no_store((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": code, "correlation_id": correlation_id })),
    )
        .into_response())
}

fn verifier_error(code: &str, error: String) -> Response {
    let correlation_id = Uuid::now_v7();
    tracing::warn!(%correlation_id, error = %error, error_code = code, "WebAuthn verifier rejected ceremony");
    no_store((
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": code, "correlation_id": correlation_id })),
    )
        .into_response())
}

fn passkey_store_error(code: &str, error: PasskeyStoreError) -> Response {
    let correlation_id = Uuid::now_v7();
    tracing::error!(%correlation_id, error = %error, error_code = code, "passkey state failure");
    no_store((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": code, "correlation_id": correlation_id })),
    )
        .into_response())
}

fn store_error(code: &str, error: StoreError) -> Response {
    let correlation_id = Uuid::now_v7();
    tracing::error!(%correlation_id, error = %error, error_code = code, "passkey session failure");
    no_store((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": code, "correlation_id": correlation_id })),
    )
        .into_response())
}

fn policy_error(code: &str, error: impl std::fmt::Display) -> Response {
    let correlation_id = Uuid::now_v7();
    tracing::error!(%correlation_id, error = %error, error_code = code, "passkey authorization failure");
    no_store((
        StatusCode::BAD_GATEWAY,
        Json(json!({ "error": code, "correlation_id": correlation_id })),
    )
        .into_response())
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn not_found() -> Response {
    api_error(StatusCode::NOT_FOUND, "NOT_FOUND")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_authlink_session_cookie() {
        let id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("theme=x; {SESSION_COOKIE}={id}; other=y")).unwrap(),
        );
        assert_eq!(session_id_from_headers(&headers), Some(id));
    }

    #[test]
    fn verifier_credential_never_contains_private_material() {
        let credential = PasskeyCredentialRecord {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            identity_id: Uuid::now_v7(),
            credential_id: "cred".into(),
            public_key: vec![1, 2, 3],
            counter: 0,
            transports: vec!["internal".into()],
            aaguid: None,
            attestation_format: None,
            credential_device_type: "multiDevice".into(),
            credential_backed_up: true,
        };
        let value = verifier_credential(&credential);
        assert!(value.get("public_key_b64").is_some());
        assert!(value.get("private_key").is_none());
    }
}
