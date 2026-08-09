use authlink_device::{
    challenge_message_b64, fingerprint, verify_b64_signature, ChallengeContext, DeviceChallengeAction,
    P256PublicJwk, CHALLENGE_BYTES, DEVICE_KEY_ALG,
};
use authlink_policy::{OpenFgaClient, PolicyCheck, RelationshipTuple};
use authlink_store::{AuthlinkStore, SessionRecord, StoreError, TrustedDeviceMetadata};
use axum::{
    extract::{Path, State},
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, COOKIE},
        HeaderMap, HeaderValue, Method, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{env, net::SocketAddr};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;

const SESSION_COOKIE: &str = "authlink_session";
const CHALLENGE_TTL_SECONDS: i64 = 120;

#[derive(Clone)]
struct AppState {
    store: AuthlinkStore,
    policy: Option<OpenFgaClient>,
    policy_dev_bypass: bool,
}

#[derive(Debug, Serialize)]
struct Health<'a> {
    status: &'a str,
    service: &'a str,
}

#[derive(Debug, Serialize)]
struct DeviceRuntimeStatus {
    database: &'static str,
    authorization: &'static str,
    proof_algorithm: &'static str,
    challenge_ttl_seconds: i64,
}

#[derive(Debug, Serialize)]
struct ChallengeResponse {
    challenge_id: Uuid,
    action: DeviceChallengeAction,
    message_b64: String,
    expires_in_seconds: i64,
}

#[derive(Debug, Deserialize)]
struct EnrollCompleteRequest {
    challenge_id: Uuid,
    public_key: P256PublicJwk,
    signature_b64: String,
    platform: String,
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VerifyDeviceRequest {
    challenge_id: Uuid,
    signature_b64: String,
}

#[derive(Debug, Serialize)]
struct DeviceResponse {
    id: Uuid,
    device_public_id: String,
    platform: String,
    display_name: Option<String>,
    trust_state: String,
    key_alg: Option<String>,
    current_session: bool,
}

#[derive(Debug, Serialize)]
struct DeviceListResponse {
    devices: Vec<DeviceResponse>,
}

#[derive(Debug, Serialize)]
struct AssuranceResponse {
    device: DeviceResponse,
    auth_strength: &'static str,
    trusted_device: bool,
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
        .expect("DATABASE_URL is mandatory for AuthLink Device");
    let store = AuthlinkStore::connect(&database_url)
        .await
        .expect("AuthLink Device could not connect to PostgreSQL");

    let policy = OpenFgaClient::from_env().expect("valid OpenFGA configuration");
    let policy_dev_bypass = !is_production
        && env::var("AUTHLINK_POLICY_DEV_BYPASS")
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false);
    if policy.is_none() && !policy_dev_bypass {
        panic!("OpenFGA is mandatory for AuthLink Device; development bypass must be explicit");
    }

    let web_url = env::var("AUTHLINK_WEB_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:5173".into())
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
        store,
        policy,
        policy_dev_bypass,
    };

    let app = Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/authlink/devices/status", get(runtime_status))
        .route("/api/v1/authlink/devices", get(list_devices))
        .route("/api/v1/authlink/devices/enroll/challenge", post(enroll_challenge))
        .route("/api/v1/authlink/devices/enroll/complete", post(enroll_complete))
        .route("/api/v1/authlink/devices/{id}/challenge", post(bind_challenge))
        .route("/api/v1/authlink/devices/{id}/verify", post(bind_complete))
        .route("/api/v1/authlink/devices/{id}/revoke", post(revoke_device))
        .fallback(not_found)
        .with_state(state)
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = env::var("AUTHLINK_DEVICE_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8789".into())
        .parse()
        .expect("valid AUTHLINK_DEVICE_ADDR");
    tracing::info!(%addr, %environment, "AuthLink Device listening");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind AuthLink Device");
    axum::serve(listener, app).await.expect("serve AuthLink Device");
}

async fn health() -> Json<Health<'static>> {
    Json(Health {
        status: "ok",
        service: "authlink-device",
    })
}

async fn runtime_status(State(state): State<AppState>) -> Json<DeviceRuntimeStatus> {
    Json(DeviceRuntimeStatus {
        database: "postgres",
        authorization: if state.policy.is_some() { "openfga" } else { "development-bypass" },
        proof_algorithm: DEVICE_KEY_ALG,
        challenge_ttl_seconds: CHALLENGE_TTL_SECONDS,
    })
}

async fn enroll_challenge(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let session = match authorize_identity(&state, &headers, "can_manage").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    issue_challenge(&state, &session, None, DeviceChallengeAction::Enroll).await
}

async fn enroll_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<EnrollCompleteRequest>,
) -> Response {
    let session = match authorize_identity(&state, &headers, "can_manage").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if !valid_platform(&request.platform) || !valid_display_name(request.display_name.as_deref()) {
        return api_error(StatusCode::UNPROCESSABLE_ENTITY, "DEVICE_METADATA_INVALID");
    }

    let challenge = match state
        .store
        .consume_device_challenge(
            request.challenge_id,
            session.tenant_id,
            session.identity_id,
            session.id,
            DeviceChallengeAction::Enroll.as_str(),
        )
        .await
    {
        Ok(Some(challenge)) => challenge,
        Ok(None) => return api_error(StatusCode::CONFLICT, "DEVICE_CHALLENGE_INVALID_OR_EXPIRED"),
        Err(error) => return store_error("DEVICE_CHALLENGE_CONSUME_FAILED", error),
    };

    let message_b64 = match challenge_message_b64(&ChallengeContext {
        challenge_id: challenge.id,
        session_id: session.id,
        identity_id: session.identity_id,
        action: DeviceChallengeAction::Enroll,
        nonce: &challenge.nonce,
    }) {
        Ok(message) => message,
        Err(error) => return crypto_error("DEVICE_CHALLENGE_RECONSTRUCTION_FAILED", error),
    };
    if let Err(error) = verify_b64_signature(&request.public_key, &message_b64, &request.signature_b64) {
        return crypto_error("DEVICE_SIGNATURE_INVALID", error);
    }

    let device_public_id = match fingerprint(&request.public_key) {
        Ok(value) => value,
        Err(error) => return crypto_error("DEVICE_PUBLIC_KEY_INVALID", error),
    };
    let public_key_json = match serde_json::to_value(&request.public_key) {
        Ok(value) => value,
        Err(_) => return internal_error("DEVICE_PUBLIC_KEY_SERIALIZATION_FAILED"),
    };
    let proposed_id = Uuid::now_v7();
    let device = match state
        .store
        .upsert_unrevoked_device(
            proposed_id,
            session.tenant_id,
            session.identity_id,
            &device_public_id,
            &request.platform,
            request.display_name.as_deref(),
            DEVICE_KEY_ALG,
            &public_key_json,
        )
        .await
    {
        Ok(Some(device)) => device,
        Ok(None) => return api_error(StatusCode::CONFLICT, "DEVICE_KEY_REVOKED"),
        Err(error) => return store_error("DEVICE_WRITE_FAILED", error),
    };

    if let Err(response) = ensure_device_owner(&state, session.identity_id, device.id).await {
        return response;
    }
    match state
        .store
        .mark_device_trusted(session.tenant_id, session.identity_id, device.id)
        .await
    {
        Ok(true) => {}
        Ok(false) => return api_error(StatusCode::CONFLICT, "DEVICE_TRUST_STATE_CHANGED"),
        Err(error) => return store_error("DEVICE_TRUST_WRITE_FAILED", error),
    }
    if let Err(response) = bind_session(&state, &session, device.id).await {
        return response;
    }

    no_store((
        StatusCode::CREATED,
        Json(AssuranceResponse {
            device: DeviceResponse {
                id: device.id,
                device_public_id,
                platform: request.platform,
                display_name: request.display_name,
                trust_state: "trusted".into(),
                key_alg: Some(DEVICE_KEY_ALG.into()),
                current_session: true,
            },
            auth_strength: "oidc+device-possession",
            trusted_device: true,
        }),
    )
        .into_response())
}

async fn bind_challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
) -> Response {
    let session = match authorize_identity(&state, &headers, "can_manage").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let device = match load_owned_device(&state, &session, device_id).await {
        Ok(device) => device,
        Err(response) => return response,
    };
    if device.public_key_jwk.is_none() || device.key_alg.as_deref() != Some(DEVICE_KEY_ALG) {
        return api_error(StatusCode::CONFLICT, "DEVICE_KEY_UNAVAILABLE");
    }
    issue_challenge(&state, &session, Some(device_id), DeviceChallengeAction::BindSession).await
}

async fn bind_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
    Json(request): Json<VerifyDeviceRequest>,
) -> Response {
    let session = match authorize_identity(&state, &headers, "can_manage").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let device = match load_owned_device(&state, &session, device_id).await {
        Ok(device) => device,
        Err(response) => return response,
    };

    let challenge = match state
        .store
        .consume_device_challenge(
            request.challenge_id,
            session.tenant_id,
            session.identity_id,
            session.id,
            DeviceChallengeAction::BindSession.as_str(),
        )
        .await
    {
        Ok(Some(challenge)) if challenge.device_id == Some(device_id) => challenge,
        Ok(_) => return api_error(StatusCode::CONFLICT, "DEVICE_CHALLENGE_INVALID_OR_EXPIRED"),
        Err(error) => return store_error("DEVICE_CHALLENGE_CONSUME_FAILED", error),
    };

    let public_key: P256PublicJwk = match device.public_key_jwk {
        Some(value) => match serde_json::from_value(value) {
            Ok(key) => key,
            Err(_) => return internal_error("DEVICE_PUBLIC_KEY_CORRUPT"),
        },
        None => return api_error(StatusCode::CONFLICT, "DEVICE_KEY_UNAVAILABLE"),
    };
    let message_b64 = match challenge_message_b64(&ChallengeContext {
        challenge_id: challenge.id,
        session_id: session.id,
        identity_id: session.identity_id,
        action: DeviceChallengeAction::BindSession,
        nonce: &challenge.nonce,
    }) {
        Ok(message) => message,
        Err(error) => return crypto_error("DEVICE_CHALLENGE_RECONSTRUCTION_FAILED", error),
    };
    if let Err(error) = verify_b64_signature(&public_key, &message_b64, &request.signature_b64) {
        return crypto_error("DEVICE_SIGNATURE_INVALID", error);
    }
    if let Err(response) = bind_session(&state, &session, device_id).await {
        return response;
    }

    no_store(Json(AssuranceResponse {
        device: DeviceResponse {
            id: device.id,
            device_public_id: device.device_public_id,
            platform: device.platform,
            display_name: device.display_name,
            trust_state: device.trust_state,
            key_alg: device.key_alg,
            current_session: true,
        },
        auth_strength: "oidc+device-possession",
        trusted_device: true,
    })
    .into_response())
}

async fn list_devices(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let session = match authorize_identity(&state, &headers, "can_read").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match state.store.list_trusted_devices(session.tenant_id, session.identity_id).await {
        Ok(devices) => no_store(Json(DeviceListResponse {
            devices: devices
                .into_iter()
                .map(|device| metadata_response(device, session.trusted_device_id))
                .collect(),
        })
        .into_response()),
        Err(error) => store_error("DEVICE_LIST_FAILED", error),
    }
}

async fn revoke_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
) -> Response {
    let session = match authorize_identity(&state, &headers, "can_manage").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = check_device_relation(&state, session.identity_id, device_id, "can_revoke").await {
        return response;
    }
    match state
        .store
        .revoke_trusted_device(session.tenant_id, session.identity_id, device_id)
        .await
    {
        Ok(true) => no_store(Json(serde_json::json!({
            "id": device_id,
            "state": "revoked",
            "bound_sessions_revoked": true
        }))
        .into_response()),
        Ok(false) => api_error(StatusCode::NOT_FOUND, "DEVICE_NOT_FOUND"),
        Err(error) => store_error("DEVICE_REVOKE_FAILED", error),
    }
}

async fn issue_challenge(
    state: &AppState,
    session: &SessionRecord,
    device_id: Option<Uuid>,
    action: DeviceChallengeAction,
) -> Response {
    let mut nonce = [0_u8; CHALLENGE_BYTES];
    if let Err(error) = getrandom::fill(&mut nonce) {
        tracing::error!(error = %error, "device challenge entropy failed");
        return internal_error("DEVICE_ENTROPY_FAILED");
    }
    let challenge_id = Uuid::now_v7();
    if let Err(error) = state
        .store
        .create_device_challenge(
            challenge_id,
            session.tenant_id,
            session.identity_id,
            session.id,
            device_id,
            action.as_str(),
            &nonce,
            CHALLENGE_TTL_SECONDS,
        )
        .await
    {
        return store_error("DEVICE_CHALLENGE_WRITE_FAILED", error);
    }
    let message_b64 = match challenge_message_b64(&ChallengeContext {
        challenge_id,
        session_id: session.id,
        identity_id: session.identity_id,
        action,
        nonce: &nonce,
    }) {
        Ok(message) => message,
        Err(error) => return crypto_error("DEVICE_CHALLENGE_BUILD_FAILED", error),
    };
    no_store(Json(ChallengeResponse {
        challenge_id,
        action,
        message_b64,
        expires_in_seconds: CHALLENGE_TTL_SECONDS,
    })
    .into_response())
}

async fn bind_session(state: &AppState, session: &SessionRecord, device_id: Uuid) -> Result<(), Response> {
    match state
        .store
        .bind_session_to_trusted_device(session.id, session.tenant_id, session.identity_id, device_id)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(api_error(StatusCode::CONFLICT, "SESSION_OR_DEVICE_STATE_CHANGED")),
        Err(error) => Err(store_error("SESSION_DEVICE_BIND_FAILED", error)),
    }
}

async fn load_owned_device(
    state: &AppState,
    session: &SessionRecord,
    device_id: Uuid,
) -> Result<authlink_store::TrustedDeviceRecord, Response> {
    check_device_relation(state, session.identity_id, device_id, "can_read").await?;
    match state
        .store
        .load_trusted_device(session.tenant_id, session.identity_id, device_id)
        .await
    {
        Ok(Some(device)) => Ok(device),
        Ok(None) => Err(api_error(StatusCode::NOT_FOUND, "DEVICE_NOT_FOUND")),
        Err(error) => Err(store_error("DEVICE_LOAD_FAILED", error)),
    }
}

async fn authorize_identity(
    state: &AppState,
    headers: &HeaderMap,
    relation: &str,
) -> Result<SessionRecord, Response> {
    let session_id = session_id_from_headers(headers).ok_or_else(unauthorized)?;
    let session = match state.store.load_active_session(session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => return Err(unauthorized()),
        Err(error) => return Err(store_error("SESSION_LOAD_FAILED", error)),
    };

    if let Some(policy) = &state.policy {
        let check = PolicyCheck {
            user: fga_user(session.identity_id),
            relation: relation.to_owned(),
            object: fga_identity(session.identity_id),
        };
        return match policy.check(&check).await {
            Ok(decision) if decision.allowed => Ok(session),
            Ok(_) => Err(api_error(StatusCode::FORBIDDEN, "DEVICE_PERMISSION_DENIED")),
            Err(error) => Err(policy_error("POLICY_UPSTREAM_FAILED", error)),
        };
    }
    if state.policy_dev_bypass {
        return Ok(session);
    }
    Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "POLICY_UNAVAILABLE"))
}

async fn ensure_device_owner(state: &AppState, identity_id: Uuid, device_id: Uuid) -> Result<(), Response> {
    if let Some(policy) = &state.policy {
        let tuple = RelationshipTuple {
            user: fga_user(identity_id),
            relation: "owner".into(),
            object: fga_device(device_id),
        };
        return policy.ensure_tuple(&tuple).await.map_err(|error| policy_error("DEVICE_POLICY_PROVISION_FAILED", error));
    }
    if state.policy_dev_bypass {
        return Ok(());
    }
    Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "POLICY_UNAVAILABLE"))
}

async fn check_device_relation(
    state: &AppState,
    identity_id: Uuid,
    device_id: Uuid,
    relation: &str,
) -> Result<(), Response> {
    if let Some(policy) = &state.policy {
        let check = PolicyCheck {
            user: fga_user(identity_id),
            relation: relation.into(),
            object: fga_device(device_id),
        };
        return match policy.check(&check).await {
            Ok(decision) if decision.allowed => Ok(()),
            Ok(_) => Err(api_error(StatusCode::FORBIDDEN, "DEVICE_PERMISSION_DENIED")),
            Err(error) => Err(policy_error("POLICY_UPSTREAM_FAILED", error)),
        };
    }
    if state.policy_dev_bypass {
        return Ok(());
    }
    Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "POLICY_UNAVAILABLE"))
}

fn metadata_response(device: TrustedDeviceMetadata, current_device: Option<Uuid>) -> DeviceResponse {
    DeviceResponse {
        id: device.id,
        device_public_id: device.device_public_id,
        platform: device.platform,
        display_name: device.display_name,
        trust_state: device.trust_state,
        key_alg: device.key_alg,
        current_session: current_device == Some(device.id),
    }
}

fn fga_user(identity_id: Uuid) -> String {
    format!("user:{identity_id}")
}

fn fga_identity(identity_id: Uuid) -> String {
    format!("identity:{identity_id}")
}

fn fga_device(device_id: Uuid) -> String {
    format!("device:{device_id}")
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

fn valid_platform(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 48
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn valid_display_name(value: Option<&str>) -> bool {
    value.map(|name| !name.trim().is_empty() && name.len() <= 96).unwrap_or(true)
}

fn unauthorized() -> Response {
    api_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_REQUIRED")
}

fn api_error(status: StatusCode, code: &str) -> Response {
    no_store((status, Json(serde_json::json!({ "error": code }))).into_response())
}

fn crypto_error(code: &str, error: impl std::fmt::Display) -> Response {
    let correlation_id = Uuid::now_v7();
    tracing::warn!(%correlation_id, error = %error, error_code = code, "device possession verification failed");
    no_store((
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": code, "correlation_id": correlation_id })),
    )
        .into_response())
}

fn store_error(code: &str, error: StoreError) -> Response {
    let correlation_id = Uuid::now_v7();
    tracing::error!(%correlation_id, error = %error, error_code = code, "device persistence failure");
    no_store((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": code, "correlation_id": correlation_id })),
    )
        .into_response())
}

fn policy_error(code: &str, error: impl std::fmt::Display) -> Response {
    let correlation_id = Uuid::now_v7();
    tracing::error!(%correlation_id, error = %error, error_code = code, "device authorization failure");
    no_store((
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({ "error": code, "correlation_id": correlation_id })),
    )
        .into_response())
}

fn internal_error(code: &str) -> Response {
    let correlation_id = Uuid::now_v7();
    tracing::error!(%correlation_id, error_code = code, "device service internal failure");
    no_store((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": code, "correlation_id": correlation_id })),
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
    fn extracts_only_authlink_cookie() {
        let session_id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("theme=x; {SESSION_COOKIE}={session_id}; y=z")).unwrap(),
        );
        assert_eq!(session_id_from_headers(&headers), Some(session_id));
    }

    #[test]
    fn validates_device_metadata_without_claiming_hardware_attestation() {
        assert!(valid_platform("webcrypto:p256"));
        assert!(!valid_platform("web crypto"));
        assert!(valid_display_name(Some("Notebook principal")));
        assert!(!valid_display_name(Some("")));
    }
}
