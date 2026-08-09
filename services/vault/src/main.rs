use authlink_policy::{OpenFgaClient, PolicyCheck};
use authlink_store::{AuthlinkStore, SessionRecord, StoreError, VaultItemMetadata};
use authlink_vault::{KeyRing, VaultBinding};
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
use serde_json::Value;
use std::{env, net::SocketAddr, sync::Arc};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;
use zeroize::Zeroizing;

const SESSION_COOKIE: &str = "authlink_session";
const MAX_ITEM_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
struct AppState {
    store: AuthlinkStore,
    policy: Option<OpenFgaClient>,
    policy_dev_bypass: bool,
    keys: Arc<KeyRing>,
}

#[derive(Debug, Serialize)]
struct Health<'a> {
    status: &'a str,
    service: &'a str,
}

#[derive(Debug, Serialize)]
struct VaultStatus {
    database: &'static str,
    authorization: &'static str,
    active_key_version: u32,
    encryption: &'static str,
}

#[derive(Debug, Deserialize)]
struct CreateVaultItemRequest {
    kind: String,
    purpose: String,
    payload: Value,
}

#[derive(Debug, Serialize)]
struct VaultItemSummary {
    id: Uuid,
    kind: String,
    purpose: String,
    key_version: u32,
}

#[derive(Debug, Serialize)]
struct VaultItemResponse {
    id: Uuid,
    kind: String,
    purpose: String,
    key_version: u32,
    payload: Value,
}

#[derive(Debug, Serialize)]
struct VaultListResponse {
    items: Vec<VaultItemSummary>,
}

#[derive(Debug, Serialize)]
struct MutationResponse {
    id: Uuid,
    state: &'static str,
    key_version: Option<u32>,
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
        .expect("DATABASE_URL is mandatory for AuthLink Vault");
    let store = AuthlinkStore::connect(&database_url)
        .await
        .expect("AuthLink Vault could not connect to PostgreSQL");

    let policy = OpenFgaClient::from_env().expect("valid OpenFGA configuration");
    let policy_dev_bypass = !is_production
        && env::var("AUTHLINK_POLICY_DEV_BYPASS")
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false);
    if policy.is_none() && !policy_dev_bypass {
        panic!("OpenFGA is mandatory for AuthLink Vault; development bypass must be explicit");
    }

    let encoded_keys = env::var("AUTHLINK_VAULT_KEYS")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .expect("AUTHLINK_VAULT_KEYS is mandatory for AuthLink Vault");
    let active_key_version = env::var("AUTHLINK_VAULT_ACTIVE_KEY_VERSION")
        .expect("AUTHLINK_VAULT_ACTIVE_KEY_VERSION is mandatory")
        .parse::<u32>()
        .expect("AUTHLINK_VAULT_ACTIVE_KEY_VERSION must be an integer");
    if active_key_version == 0 {
        panic!("AUTHLINK_VAULT_ACTIVE_KEY_VERSION must be positive");
    }
    let keys = Arc::new(
        KeyRing::from_encoded(active_key_version, &encoded_keys)
            .expect("AUTHLINK_VAULT_KEYS must contain valid version/base64 32-byte keys"),
    );

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
        keys,
    };

    let app = Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/authlink/vault/status", get(status))
        .route("/api/v1/authlink/vault/items", get(list_items).post(create_item))
        .route("/api/v1/authlink/vault/items/{id}", get(get_item))
        .route("/api/v1/authlink/vault/items/{id}/rotate", post(rotate_item))
        .route("/api/v1/authlink/vault/items/{id}/delete", post(delete_item))
        .fallback(not_found)
        .with_state(state)
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = env::var("AUTHLINK_VAULT_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8788".into())
        .parse()
        .expect("valid AUTHLINK_VAULT_ADDR");
    tracing::info!(%addr, %environment, active_key_version, "AuthLink Vault listening");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind AuthLink Vault");
    axum::serve(listener, app).await.expect("serve AuthLink Vault");
}

async fn health() -> Json<Health<'static>> {
    Json(Health {
        status: "ok",
        service: "authlink-vault",
    })
}

async fn status(State(state): State<AppState>) -> Json<VaultStatus> {
    Json(VaultStatus {
        database: "postgres",
        authorization: if state.policy.is_some() { "openfga" } else { "development-bypass" },
        active_key_version: state.keys.active_version(),
        encryption: authlink_vault::ALGORITHM,
    })
}

async fn list_items(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let session = match authorize(&state, &headers, "can_read").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match state.store.list_vault_items(session.tenant_id, session.identity_id).await {
        Ok(items) => no_store(Json(VaultListResponse {
            items: items.into_iter().map(summary_from).collect(),
        })
        .into_response()),
        Err(error) => store_error("VAULT_LIST_FAILED", error),
    }
}

async fn create_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateVaultItemRequest>,
) -> Response {
    let session = match authorize(&state, &headers, "can_manage").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if !valid_tag(&request.kind, 48) || !valid_tag(&request.purpose, 96) {
        return client_error(StatusCode::UNPROCESSABLE_ENTITY, "VAULT_INVALID_KIND_OR_PURPOSE");
    }

    let plaintext = match serde_json::to_vec(&request.payload) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(_) => return internal_error("VAULT_SERIALIZATION_FAILED"),
    };
    if plaintext.len() > MAX_ITEM_BYTES {
        return no_store((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({
                "error": "VAULT_ITEM_TOO_LARGE",
                "max_bytes": MAX_ITEM_BYTES
            })),
        )
            .into_response());
    }

    let id = Uuid::now_v7();
    let binding = VaultBinding::new(session.tenant_id, session.identity_id, id, request.purpose.clone());
    let envelope = match state.keys.encrypt(&binding, plaintext.as_slice()) {
        Ok(envelope) => envelope,
        Err(error) => {
            tracing::error!(%id, error = %error, "vault encryption failed");
            return internal_error("VAULT_ENCRYPTION_FAILED");
        }
    };

    if let Err(error) = state
        .store
        .create_vault_item(
            id,
            session.tenant_id,
            session.identity_id,
            &request.kind,
            &request.purpose,
            &envelope,
        )
        .await
    {
        return store_error("VAULT_WRITE_FAILED", error);
    }

    no_store((
        StatusCode::CREATED,
        Json(VaultItemSummary {
            id,
            kind: request.kind,
            purpose: request.purpose,
            key_version: envelope.key_version,
        }),
    )
        .into_response())
}

async fn get_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let session = match authorize(&state, &headers, "can_read").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let item = match state
        .store
        .load_vault_item(session.tenant_id, session.identity_id, id)
        .await
    {
        Ok(Some(item)) => item,
        Ok(None) => return vault_not_found(),
        Err(error) => return store_error("VAULT_READ_FAILED", error),
    };

    let binding = VaultBinding::new(item.tenant_id, item.identity_id, item.id, item.purpose.clone());
    let plaintext = match state.keys.decrypt(&binding, &item.envelope) {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%id, key_version = item.key_version, error = %error, "vault authentication/decryption failed");
            return internal_error("VAULT_DECRYPTION_FAILED");
        }
    };
    let payload: Value = match serde_json::from_slice(plaintext.as_slice()) {
        Ok(payload) => payload,
        Err(_) => return internal_error("VAULT_PAYLOAD_INVALID"),
    };

    no_store(Json(VaultItemResponse {
        id: item.id,
        kind: item.kind,
        purpose: item.purpose,
        key_version: item.key_version,
        payload,
    })
    .into_response())
}

async fn rotate_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let session = match authorize(&state, &headers, "can_manage").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let item = match state
        .store
        .load_vault_item(session.tenant_id, session.identity_id, id)
        .await
    {
        Ok(Some(item)) => item,
        Ok(None) => return vault_not_found(),
        Err(error) => return store_error("VAULT_READ_FAILED", error),
    };

    if item.key_version == state.keys.active_version() {
        return no_store(Json(MutationResponse {
            id,
            state: "already-current",
            key_version: Some(item.key_version),
        })
        .into_response());
    }

    let binding = VaultBinding::new(item.tenant_id, item.identity_id, item.id, item.purpose.clone());
    let rotated = match state.keys.rewrap_to_active(&binding, &item.envelope) {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(%id, error = %error, "vault DEK rewrap failed");
            return internal_error("VAULT_ROTATION_FAILED");
        }
    };

    match state
        .store
        .update_vault_envelope(
            session.tenant_id,
            session.identity_id,
            id,
            item.key_version,
            &rotated,
        )
        .await
    {
        Ok(true) => no_store(Json(MutationResponse {
            id,
            state: "rotated",
            key_version: Some(rotated.key_version),
        })
        .into_response()),
        Ok(false) => client_error(StatusCode::CONFLICT, "VAULT_ITEM_CHANGED"),
        Err(error) => store_error("VAULT_ROTATION_WRITE_FAILED", error),
    }
}

async fn delete_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let session = match authorize(&state, &headers, "can_manage").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match state
        .store
        .delete_vault_item(session.tenant_id, session.identity_id, id)
        .await
    {
        Ok(true) => no_store(Json(MutationResponse {
            id,
            state: "deleted",
            key_version: None,
        })
        .into_response()),
        Ok(false) => vault_not_found(),
        Err(error) => store_error("VAULT_DELETE_FAILED", error),
    }
}

async fn authorize(
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
            user: format!("user:{}", session.identity_id),
            relation: relation.to_owned(),
            object: format!("identity:{}", session.identity_id),
        };
        return match policy.check(&check).await {
            Ok(decision) if decision.allowed => Ok(session),
            Ok(_) => Err(client_error(StatusCode::FORBIDDEN, "VAULT_PERMISSION_DENIED")),
            Err(error) => {
                let correlation_id = Uuid::now_v7();
                tracing::error!(%correlation_id, error = %error, "vault authorization upstream failed");
                Err(no_store((
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": "POLICY_UPSTREAM_FAILED",
                        "correlation_id": correlation_id
                    })),
                )
                    .into_response()))
            }
        };
    }

    if state.policy_dev_bypass {
        return Ok(session);
    }
    Err(client_error(StatusCode::SERVICE_UNAVAILABLE, "POLICY_UNAVAILABLE"))
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

fn summary_from(item: VaultItemMetadata) -> VaultItemSummary {
    VaultItemSummary {
        id: item.id,
        kind: item.kind,
        purpose: item.purpose,
        key_version: item.key_version,
    }
}

fn valid_tag(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn unauthorized() -> Response {
    client_error(StatusCode::UNAUTHORIZED, "AUTHENTICATION_REQUIRED")
}

fn vault_not_found() -> Response {
    client_error(StatusCode::NOT_FOUND, "VAULT_ITEM_NOT_FOUND")
}

fn client_error(status: StatusCode, code: &str) -> Response {
    no_store((status, Json(serde_json::json!({ "error": code }))).into_response())
}

fn internal_error(code: &str) -> Response {
    let correlation_id = Uuid::now_v7();
    tracing::error!(%correlation_id, error_code = code, "AuthLink Vault internal failure");
    no_store((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": code, "correlation_id": correlation_id })),
    )
        .into_response())
}

fn store_error(code: &str, error: StoreError) -> Response {
    let correlation_id = Uuid::now_v7();
    tracing::error!(%correlation_id, error = %error, error_code = code, "AuthLink Vault persistence failure");
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
    client_error(StatusCode::NOT_FOUND, "NOT_FOUND")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_authlink_session_cookie() {
        let session = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("theme=dark; {SESSION_COOKIE}={session}; other=x")).unwrap(),
        );
        assert_eq!(session_id_from_headers(&headers), Some(session));
    }

    #[test]
    fn restricts_kind_and_purpose_identifiers() {
        assert!(valid_tag("credential.password", 48));
        assert!(valid_tag("credential:store", 96));
        assert!(!valid_tag("bank password", 48));
        assert!(!valid_tag("", 48));
    }
}
