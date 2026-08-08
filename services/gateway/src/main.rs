use authlink_contracts::Capability;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde::Serialize;
use std::{net::SocketAddr, sync::Arc};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

#[derive(Clone)]
struct AppState {
    capabilities: Arc<Vec<Capability>>,
}

#[derive(Serialize)]
struct Health<'a> {
    status: &'a str,
    service: &'a str,
}

#[derive(Serialize)]
struct CapabilityResponse {
    capabilities: Vec<Capability>,
}

#[derive(Serialize)]
struct SessionSummary<'a> {
    subject: &'a str,
    #[serde(rename = "authStrength")]
    auth_strength: &'a str,
    #[serde(rename = "trustedDevice")]
    trusted_device: bool,
    online: bool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    let capabilities = vec![
        cap("identity.sso", "SSO & Passkeys", "identity"),
        cap("security.guardian", "Guardian", "security"),
        cap("vault.credentials", "Vault de Senhas", "vault"),
        cap("vault.media", "Cofre de Fotos", "vault"),
        cap("social.feed", "Feed Social", "social"),
        cap("social.match", "Match & Discovery", "social"),
        cap("chat.secure", "Chat Seguro", "comms"),
        cap("mesh.nearby", "Nearby Mesh", "comms"),
        cap("knowledge.graph", "Knowledge Graph", "knowledge"),
        cap("suite.launch", "AIIA App Launcher", "suite"),
        cap("developer.integrations", "Developer Integrations", "developer"),
        cap("audit.append_only", "Audit Journal", "security"),
    ];

    let state = AppState {
        capabilities: Arc::new(capabilities),
    };

    let app = Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/authlink/capabilities", get(list_capabilities))
        .route("/api/v1/authlink/session", get(session))
        .route("/api/v1/capabilities/authlink", get(list_capabilities))
        .fallback(not_found)
        .with_state(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = "127.0.0.1:8787".parse().expect("valid gateway address");
    tracing::info!(%addr, "AuthLink gateway listening");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind gateway");
    axum::serve(listener, app).await.expect("serve gateway");
}

fn cap(id: &str, title: &str, group: &str) -> Capability {
    Capability {
        id: id.into(),
        title: title.into(),
        group: group.into(),
        enabled: true,
    }
}

async fn health() -> Json<Health<'static>> {
    Json(Health {
        status: "ok",
        service: "authlink-gateway",
    })
}

async fn list_capabilities(State(state): State<AppState>) -> Json<CapabilityResponse> {
    Json(CapabilityResponse {
        capabilities: (*state.capabilities).clone(),
    })
}

async fn session() -> Json<SessionSummary<'static>> {
    Json(SessionSummary {
        subject: "local-user",
        auth_strength: "passkey+device",
        trusted_device: true,
        online: true,
    })
}

async fn not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "NOT_FOUND" })),
    )
}
