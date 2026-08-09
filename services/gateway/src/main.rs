use authlink_contracts::{
    AdvanceOnboardingRequest, AdvanceOnboardingResponse, AuthStrength, Capability, GuardianDecision,
    GuardianSignals, OnboardingProgress, OnboardingStep, OnboardingStepId, StepStatus,
};
use authlink_guardian::evaluate;
use authlink_idp::{unconfigured_status, OidcClient, OidcMetadata, PublicOidcStatus};
use authlink_policy::{OpenFgaClient, PolicyCheck, PolicyDecision, RelationshipTuple};
use authlink_store::AuthlinkStore;
use axum::{
    extract::{Query, State},
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, COOKIE, SET_COOKIE},
        HeaderMap, HeaderValue, Method, StatusCode,
    },
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;

const SESSION_COOKIE: &str = "authlink_session";
const SESSION_TTL_SECONDS: i64 = 8 * 60 * 60;
const LOGIN_TX_TTL: Duration = Duration::from_secs(10 * 60);
const DEV_TENANT_ID: &str = "00000000-0000-7000-8000-000000000001";

#[derive(Debug, Clone, Copy)]
struct CeremonyState {
    id: Uuid,
    completed: usize,
}

#[derive(Debug)]
struct LoginTransaction {
    code_verifier: String,
    created_at: Instant,
}

#[derive(Debug, Clone)]
struct MemorySession {
    identity_id: Uuid,
    subject: String,
    display_name: Option<String>,
    auth_strength: String,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct ResolvedSession {
    session_id: Uuid,
    identity_id: Uuid,
    subject: String,
    display_name: Option<String>,
    auth_strength: String,
    trusted_device: bool,
}

#[derive(Clone)]
struct AppState {
    capabilities: Arc<Vec<Capability>>,
    ceremony: Arc<Mutex<CeremonyState>>,
    store: Option<AuthlinkStore>,
    policy: Option<OpenFgaClient>,
    policy_dev_bypass: bool,
    idp: Option<OidcClient>,
    idp_metadata: Option<OidcMetadata>,
    login_transactions: Arc<Mutex<HashMap<String, LoginTransaction>>>,
    memory_sessions: Arc<Mutex<HashMap<Uuid, MemorySession>>>,
    web_url: String,
    cookie_secure: bool,
    tenant_id: Uuid,
}

#[derive(Serialize)]
struct Health<'a> {
    status: &'a str,
    service: &'a str,
}

#[derive(Serialize)]
struct RuntimeStatus {
    database: &'static str,
    authorization: &'static str,
    authorization_dev_bypass: bool,
    ceremony_storage: &'static str,
    identity_provider: &'static str,
    session_storage: &'static str,
}

#[derive(Serialize)]
struct CapabilityResponse {
    capabilities: Vec<Capability>,
}

#[derive(Serialize)]
struct SessionSummary {
    authenticated: bool,
    subject: Option<String>,
    display_name: Option<String>,
    auth_strength: Option<String>,
    trusted_device: bool,
    online: bool,
}

#[derive(Serialize)]
struct PolicyStatus {
    configured: bool,
    dev_bypass: bool,
    mode: &'static str,
}

#[derive(Serialize)]
struct OidcStartResponse {
    authorization_url: String,
    state: String,
}

#[derive(Serialize)]
struct SelfPolicyBootstrap {
    identity_ref: String,
    user_ref: String,
    relation: &'static str,
    source: &'static str,
}

#[derive(Deserialize)]
struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    #[allow(dead_code)]
    error_description: Option<String>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    let environment = env::var("AUTHLINK_ENV").unwrap_or_else(|_| "development".into());
    let is_production = environment.eq_ignore_ascii_case("production");
    let web_url = env::var("AUTHLINK_WEB_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:5173".into())
        .trim_end_matches('/')
        .to_owned();
    let tenant_id = match env::var("AUTHLINK_DEFAULT_TENANT_ID") {
        Ok(value) => Uuid::parse_str(&value).expect("valid AUTHLINK_DEFAULT_TENANT_ID"),
        Err(_) if is_production => panic!("AUTHLINK_DEFAULT_TENANT_ID is mandatory in production"),
        Err(_) => Uuid::parse_str(DEV_TENANT_ID).expect("valid development tenant UUID"),
    };

    let policy = OpenFgaClient::from_env().expect("valid OpenFGA configuration");
    let policy_dev_bypass = !is_production
        && env::var("AUTHLINK_POLICY_DEV_BYPASS")
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(true);
    if is_production && policy.is_none() {
        panic!("OPENFGA_API_URL and OPENFGA_STORE_ID are mandatory in production");
    }
    if policy.is_none() && policy_dev_bypass {
        tracing::warn!("OpenFGA is not configured; development authorization bypass is active");
    }

    let store = match AuthlinkStore::from_env().await {
        Ok(store) => store,
        Err(error) if is_production => panic!("failed to connect AuthLink PostgreSQL store: {error}"),
        Err(error) => {
            tracing::warn!(error = %error, "PostgreSQL unavailable; using development in-memory state");
            None
        }
    };
    if is_production && store.is_none() {
        panic!("DATABASE_URL is mandatory in production");
    }

    let idp = OidcClient::from_env().expect("valid AuthLink OIDC configuration");
    let idp_metadata = if let Some(client) = &idp {
        match client.discover().await {
            Ok(metadata) => Some(metadata),
            Err(error) if is_production => panic!("OIDC discovery failed in production: {error}"),
            Err(error) => {
                tracing::warn!(error = %error, "OIDC discovery unavailable; external login disabled in development");
                None
            }
        }
    } else {
        None
    };
    if is_production && (idp.is_none() || idp_metadata.is_none()) {
        panic!("AUTHLINK_OIDC_ISSUER and a reachable OIDC provider are mandatory in production");
    }

    let initial_ceremony = CeremonyState { id: Uuid::now_v7(), completed: 0 };
    if let Some(database) = &store {
        database
            .ensure_ceremony(initial_ceremony.id, onboarding_template().len())
            .await
            .expect("authlink migrations must be applied before gateway startup");
    }

    let capabilities = vec![
        cap("identity.sso", "SSO & credential assurance", "identity"),
        cap("identity.oidc-pkce", "OIDC Authorization Code + PKCE", "identity"),
        cap("identity.onboarding", "Cerimônia de identidade", "identity"),
        cap("authorization.openfga", "OpenFGA ReBAC", "identity"),
        cap("authorization.session-bound", "Session-bound authorization", "identity"),
        cap("persistence.postgres", "PostgreSQL authority", "platform"),
        cap("security.device-possession", "Trusted device possession", "security"),
        cap("security.guardian", "Guardian", "security"),
        cap("security.step_up", "Step-up authentication", "security"),
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
        ceremony: Arc::new(Mutex::new(initial_ceremony)),
        store,
        policy,
        policy_dev_bypass,
        idp,
        idp_metadata,
        login_transactions: Arc::new(Mutex::new(HashMap::new())),
        memory_sessions: Arc::new(Mutex::new(HashMap::new())),
        web_url: web_url.clone(),
        cookie_secure: is_production,
        tenant_id,
    };

    let allowed_origin = HeaderValue::from_str(&web_url).expect("AUTHLINK_WEB_URL must be a valid HTTP origin");
    let cors = CorsLayer::new()
        .allow_origin(allowed_origin)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([CONTENT_TYPE, AUTHORIZATION])
        .allow_credentials(true);

    let app = Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/authlink/runtime", get(runtime_status))
        .route("/api/v1/authlink/capabilities", get(list_capabilities))
        .route("/api/v1/authlink/session", get(session))
        .route("/api/v1/authlink/session/logout", post(logout))
        .route("/api/v1/authlink/oidc/status", get(oidc_status))
        .route("/api/v1/authlink/oidc/start", post(oidc_start))
        .route("/api/v1/authlink/oidc/callback", get(oidc_callback))
        .route("/api/v1/authlink/onboarding", get(get_onboarding))
        .route("/api/v1/authlink/onboarding/advance", post(advance_onboarding))
        .route("/api/v1/authlink/onboarding/reset", post(reset_onboarding))
        .route("/api/v1/authlink/security/overview", get(security_overview))
        .route("/api/v1/authlink/security/evaluate", post(evaluate_guardian))
        .route("/api/v1/authlink/policy/status", get(policy_status))
        .route("/api/v1/authlink/policy/check", post(policy_check))
        .route("/api/v1/authlink/policy/bootstrap-self", post(bootstrap_self_policy))
        .route("/api/v1/capabilities/authlink", get(list_capabilities))
        .fallback(not_found)
        .with_state(state)
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = env::var("AUTHLINK_GATEWAY_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8787".into())
        .parse()
        .expect("valid AUTHLINK_GATEWAY_ADDR");
    tracing::info!(%addr, environment = %environment, "AuthLink gateway listening");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind gateway");
    axum::serve(listener, app).await.expect("serve gateway");
}

fn cap(id: &str, title: &str, group: &str) -> Capability {
    Capability { id: id.into(), title: title.into(), group: group.into(), enabled: true }
}

fn onboarding_template() -> Vec<(OnboardingStepId, &'static str, &'static str, bool, &'static str)> {
    vec![
        (OnboardingStepId::Welcome, "Bem-vindo ao AuthLink", "Sua identidade universal começa neste dispositivo.", true, "identity.enroll"),
        (OnboardingStepId::Account, "Criar conta ou entrar", "Vincule seu AuthLink ID e escolha o método inicial de acesso.", true, "identity.account"),
        (OnboardingStepId::DeviceIntegrity, "Prova deste dispositivo", "Trusted Device usa uma prova criptográfica separada da simples progressão desta cerimônia.", true, "device.trust"),
        (OnboardingStepId::FaceCapture, "Captura facial", "Mapeamento facial para proofing e referência PERZON autorizada.", true, "biometric.enroll"),
        (OnboardingStepId::Liveness, "Prova de vida", "PAD/liveness confirma presença real sem manter vídeo bruto por padrão.", true, "biometric.liveness"),
        (OnboardingStepId::Document, "Documento oficial", "OCR e validação documental quando a finalidade exigir.", false, "identity.document"),
        (OnboardingStepId::IdentityMatch, "Correspondência de identidade", "Combinamos evidências e elevamos revisão quando o risco pede.", true, "identity.match"),
        (OnboardingStepId::Consent, "Consentimentos", "Você escolhe finalidade, escopo, retenção e uso de cada dado sensível.", true, "consent.grant"),
        (OnboardingStepId::Passkey, "Passkey / WebAuthn", "Reservado para assertion WebAuthn comprovada; MFA genérico do IdP não é promovido a passkey.", false, "credential.passkey"),
        (OnboardingStepId::SecondFactor, "Segundo fator", "Adicione security key ou método alternativo de recuperação forte.", false, "credential.second-factor"),
        (OnboardingStepId::Recovery, "Recuperação", "Gere códigos e configure contatos confiáveis sem criar backdoor.", true, "identity.recovery"),
        (OnboardingStepId::VaultSetup, "Configurar Vault", "Crie o cofre local e a hierarquia de chaves para credenciais e mídia.", true, "vault.bootstrap"),
        (OnboardingStepId::SovereignIdentity, "Identidade soberana", "Revise credenciais, dispositivos, scopes e trust score.", true, "identity.activate"),
        (OnboardingStepId::AvatarOptIn, "Referência para avatar PEZON", "Opcional: autorize uma referência separada para seu gêmeo digital.", false, "avatar.reference"),
        (OnboardingStepId::AuditProof, "Prova e auditoria", "Registramos o resultado mínimo da cerimônia e a trilha de consentimento.", true, "audit.write"),
        (OnboardingStepId::Complete, "Acesso liberado", "A cerimônia terminou; assurance de sessão continua dependente das evidências criptográficas reais.", true, "session.activate"),
    ]
}

fn step_slug(step: OnboardingStepId) -> &'static str {
    match step {
        OnboardingStepId::Welcome => "welcome",
        OnboardingStepId::Account => "account",
        OnboardingStepId::DeviceIntegrity => "device-integrity",
        OnboardingStepId::FaceCapture => "face-capture",
        OnboardingStepId::Liveness => "liveness",
        OnboardingStepId::Document => "document",
        OnboardingStepId::IdentityMatch => "identity-match",
        OnboardingStepId::Consent => "consent",
        OnboardingStepId::Passkey => "passkey",
        OnboardingStepId::SecondFactor => "second-factor",
        OnboardingStepId::Recovery => "recovery",
        OnboardingStepId::VaultSetup => "vault-setup",
        OnboardingStepId::SovereignIdentity => "sovereign-identity",
        OnboardingStepId::AvatarOptIn => "avatar-opt-in",
        OnboardingStepId::AuditProof => "audit-proof",
        OnboardingStepId::Complete => "complete",
    }
}

fn auth_strength_slug(strength: &AuthStrength) -> &'static str {
    match strength {
        AuthStrength::Anonymous => "anonymous",
        AuthStrength::Password => "password",
        AuthStrength::Passkey => "passkey",
        AuthStrength::PasskeyDevice => "passkey-device",
        AuthStrength::StepUp => "step-up",
    }
}

fn progress_from(state: &CeremonyState) -> OnboardingProgress {
    let template = onboarding_template();
    let total = template.len();
    let completed = state.completed.min(total);
    let steps = template
        .into_iter()
        .enumerate()
        .map(|(index, (id, title, subtitle, required, purpose))| OnboardingStep {
            id,
            title: title.into(),
            subtitle: subtitle.into(),
            status: if index < completed {
                StepStatus::Complete
            } else if index == completed && completed < total {
                StepStatus::Active
            } else {
                StepStatus::Pending
            },
            required,
            purpose: purpose.into(),
        })
        .collect();

    // Ceremony progression is workflow state, not authentication evidence.
    // Auth strength and trusted-device state are derived from the canonical session instead.
    OnboardingProgress {
        ceremony_id: state.id,
        current_index: completed.min(total.saturating_sub(1)),
        completed,
        total,
        steps,
        auth_strength: AuthStrength::Anonymous,
        trusted_device: false,
        risk_score: 24,
    }
}

fn local_ceremony(state: &AppState) -> Result<CeremonyState, &'static str> {
    state.ceremony.lock().map(|guard| *guard).map_err(|_| "CEREMONY_STATE_UNAVAILABLE")
}

async fn ceremony_snapshot(state: &AppState) -> Result<CeremonyState, String> {
    let local = local_ceremony(state).map_err(str::to_owned)?;
    if let Some(store) = &state.store {
        let record = store.load_ceremony(local.id).await.map_err(|error| error.to_string())?;
        Ok(CeremonyState { id: record.id, completed: record.completed_steps })
    } else {
        Ok(local)
    }
}

async fn health() -> Json<Health<'static>> {
    Json(Health { status: "ok", service: "authlink-gateway" })
}

async fn runtime_status(State(state): State<AppState>) -> Json<RuntimeStatus> {
    Json(RuntimeStatus {
        database: if state.store.is_some() { "postgres" } else { "memory-development" },
        authorization: if state.policy.is_some() { "openfga" } else if state.policy_dev_bypass { "development-bypass" } else { "unavailable" },
        authorization_dev_bypass: state.policy_dev_bypass,
        ceremony_storage: if state.store.is_some() { "postgres-optimistic" } else { "memory-development" },
        identity_provider: if state.idp_metadata.is_some() { "oidc-ready" } else { "unconfigured" },
        session_storage: if state.store.is_some() { "postgres-opaque-cookie" } else { "memory-development" },
    })
}

async fn list_capabilities(State(state): State<AppState>) -> Json<CapabilityResponse> {
    Json(CapabilityResponse { capabilities: (*state.capabilities).clone() })
}

async fn oidc_status(State(state): State<AppState>) -> Json<PublicOidcStatus> {
    Json(match &state.idp {
        Some(client) => client.public_status(state.idp_metadata.as_ref()),
        None => unconfigured_status(),
    })
}

async fn oidc_start(State(state): State<AppState>) -> impl IntoResponse {
    let Some(client) = &state.idp else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "OIDC_NOT_CONFIGURED" }))).into_response();
    };
    let Some(metadata) = &state.idp_metadata else {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "OIDC_DISCOVERY_UNAVAILABLE" }))).into_response();
    };
    let transaction = match client.begin_authorization(metadata) {
        Ok(transaction) => transaction,
        Err(error) => return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": "OIDC_START_FAILED", "developer_message": error.to_string() })),
        ).into_response(),
    };

    {
        let mut logins = match state.login_transactions.lock() {
            Ok(logins) => logins,
            Err(_) => return internal_error("OIDC_TRANSACTION_STATE_UNAVAILABLE"),
        };
        logins.retain(|_, value| value.created_at.elapsed() <= LOGIN_TX_TTL);
        logins.insert(transaction.state.clone(), LoginTransaction {
            code_verifier: transaction.code_verifier,
            created_at: Instant::now(),
        });
    }

    (
        StatusCode::OK,
        Json(OidcStartResponse { authorization_url: transaction.authorization_url, state: transaction.state }),
    ).into_response()
}

async fn oidc_callback(State(state): State<AppState>, Query(query): Query<OidcCallbackQuery>) -> axum::response::Response {
    if query.error.is_some() {
        return oidc_failure_redirect(&state, "provider_denied");
    }
    let (Some(code), Some(returned_state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return oidc_failure_redirect(&state, "missing_code_or_state");
    };
    let transaction = {
        let mut logins = match state.login_transactions.lock() {
            Ok(logins) => logins,
            Err(_) => return oidc_failure_redirect(&state, "transaction_store_unavailable"),
        };
        logins.retain(|_, value| value.created_at.elapsed() <= LOGIN_TX_TTL);
        logins.remove(returned_state)
    };
    let Some(transaction) = transaction else {
        return oidc_failure_redirect(&state, "invalid_or_expired_state");
    };
    if transaction.created_at.elapsed() > LOGIN_TX_TTL {
        return oidc_failure_redirect(&state, "expired_state");
    }

    let (Some(client), Some(metadata)) = (&state.idp, &state.idp_metadata) else {
        return oidc_failure_redirect(&state, "idp_unavailable");
    };
    let token = match client.exchange_code(metadata, code, &transaction.code_verifier).await {
        Ok(token) => token,
        Err(error) => {
            tracing::warn!(error = %error, "OIDC code exchange failed");
            return oidc_failure_redirect(&state, "code_exchange_failed");
        }
    };
    let user = match client.userinfo(metadata, &token.access_token).await {
        Ok(user) => user,
        Err(error) => {
            tracing::warn!(error = %error, "OIDC userinfo failed");
            return oidc_failure_redirect(&state, "userinfo_failed");
        }
    };
    drop(token);

    let session_id = Uuid::new_v4();
    let display_name = user.name.clone().or(user.preferred_username.clone());
    let identity_id = if let Some(store) = &state.store {
        match store.upsert_oidc_identity(state.tenant_id, &user.sub, display_name.as_deref()).await {
            Ok(identity_id) => identity_id,
            Err(error) => {
                tracing::error!(error = %error, "failed to persist OIDC identity");
                return oidc_failure_redirect(&state, "identity_persistence_failed");
            }
        }
    } else {
        Uuid::now_v7()
    };

    if let Some(policy) = &state.policy {
        let tuple = self_owner_tuple(identity_id);
        if let Err(error) = policy.ensure_tuple(&tuple).await {
            tracing::error!(error = %error, %identity_id, "failed to provision AuthLink identity ownership relation");
            return oidc_failure_redirect(&state, "authorization_provisioning_failed");
        }
    } else if !state.policy_dev_bypass {
        return oidc_failure_redirect(&state, "authorization_unavailable");
    }

    if let Some(store) = &state.store {
        if let Err(error) = store
            .create_session(session_id, state.tenant_id, identity_id, "authlink-web", "suite.access", "oidc", SESSION_TTL_SECONDS)
            .await
        {
            tracing::error!(error = %error, "failed to persist AuthLink session");
            return oidc_failure_redirect(&state, "session_persistence_failed");
        }
    } else {
        let mut sessions = match state.memory_sessions.lock() {
            Ok(sessions) => sessions,
            Err(_) => return oidc_failure_redirect(&state, "session_store_unavailable"),
        };
        sessions.retain(|_, value| value.expires_at > Instant::now());
        sessions.insert(session_id, MemorySession {
            identity_id,
            subject: user.sub,
            display_name,
            auth_strength: "oidc".into(),
            expires_at: Instant::now() + Duration::from_secs(SESSION_TTL_SECONDS as u64),
        });
    }

    let target = format!("{}?authlink_login=success#/feed", state.web_url);
    let mut response = Redirect::to(&target).into_response();
    let cookie = build_session_cookie(session_id, state.cookie_secure, SESSION_TTL_SECONDS);
    response.headers_mut().insert(SET_COOKIE, HeaderValue::from_str(&cookie).expect("valid session cookie"));
    response.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn session(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    match resolve_session(&state, &headers).await {
        Ok(session) => (
            StatusCode::OK,
            Json(SessionSummary {
                authenticated: true,
                subject: Some(session.subject),
                display_name: session.display_name,
                auth_strength: Some(session.auth_strength),
                trusted_device: session.trusted_device,
                online: true,
            }),
        ).into_response(),
        Err(response) => response,
    }
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(session_id) = session_id_from_headers(&headers) {
        if let Some(store) = &state.store {
            if let Err(error) = store.revoke_session(session_id).await {
                tracing::error!(error = %error, "failed to revoke AuthLink session");
            }
        } else if let Ok(mut sessions) = state.memory_sessions.lock() {
            sessions.remove(&session_id);
        }
    }
    let mut response = (StatusCode::NO_CONTENT, ()).into_response();
    let cookie = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}", if state.cookie_secure { "; Secure" } else { "" });
    response.headers_mut().insert(SET_COOKIE, HeaderValue::from_str(&cookie).expect("valid logout cookie"));
    response.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn get_onboarding(State(state): State<AppState>) -> impl IntoResponse {
    match ceremony_snapshot(&state).await {
        Ok(ceremony) => (StatusCode::OK, Json(progress_from(&ceremony))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "CEREMONY_LOAD_FAILED", "developer_message": error })),
        ).into_response(),
    }
}

async fn advance_onboarding(
    State(state): State<AppState>,
    Json(request): Json<AdvanceOnboardingRequest>,
) -> impl IntoResponse {
    let ceremony = match ceremony_snapshot(&state).await {
        Ok(value) => value,
        Err(error) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "CEREMONY_LOAD_FAILED", "developer_message": error })),
        ).into_response(),
    };

    let template = onboarding_template();
    if ceremony.completed >= template.len() {
        return (
            StatusCode::OK,
            Json(AdvanceOnboardingResponse {
                accepted: true,
                progress: progress_from(&ceremony),
                message: Some("Cerimônia já concluída".into()),
            }),
        ).into_response();
    }

    let expected = template[ceremony.completed];
    if request.step != expected.0 {
        return (
            StatusCode::CONFLICT,
            Json(AdvanceOnboardingResponse {
                accepted: false,
                progress: progress_from(&ceremony),
                message: Some(format!("Etapa fora de ordem. Esperada: {:?}", expected.0)),
            }),
        ).into_response();
    }
    if request.skip && expected.3 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(AdvanceOnboardingResponse {
                accepted: false,
                progress: progress_from(&ceremony),
                message: Some("Esta etapa é obrigatória".into()),
            }),
        ).into_response();
    }

    let next = CeremonyState { id: ceremony.id, completed: ceremony.completed + 1 };
    let next_progress = progress_from(&next);
    if let Some(store) = &state.store {
        let next_step = if next.completed < template.len() { step_slug(template[next.completed].0) } else { "complete" };
        let updated = match store.advance_ceremony(
            ceremony.id,
            ceremony.completed,
            next.completed,
            next_step,
            auth_strength_slug(&next_progress.auth_strength),
            next_progress.trusted_device,
            next_progress.risk_score,
            next.completed >= template.len(),
        ).await {
            Ok(updated) => updated,
            Err(error) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "CEREMONY_WRITE_FAILED", "developer_message": error.to_string() })),
            ).into_response(),
        };
        if !updated {
            let latest = ceremony_snapshot(&state).await.unwrap_or(ceremony);
            return (
                StatusCode::CONFLICT,
                Json(AdvanceOnboardingResponse {
                    accepted: false,
                    progress: progress_from(&latest),
                    message: Some("A cerimônia foi atualizada em outra sessão. Recarregue e continue.".into()),
                }),
            ).into_response();
        }
    } else {
        let mut local = match state.ceremony.lock() {
            Ok(value) => value,
            Err(_) => return internal_error("CEREMONY_STATE_UNAVAILABLE"),
        };
        if local.id != ceremony.id || local.completed != ceremony.completed {
            return (
                StatusCode::CONFLICT,
                Json(AdvanceOnboardingResponse {
                    accepted: false,
                    progress: progress_from(&local),
                    message: Some("A cerimônia local mudou. Recarregue e continue.".into()),
                }),
            ).into_response();
        }
        local.completed = next.completed;
    }

    (
        StatusCode::OK,
        Json(AdvanceOnboardingResponse {
            accepted: true,
            progress: next_progress,
            message: request.evidence_ref.map(|_| "Evidência referenciada com sucesso".into()),
        }),
    ).into_response()
}

async fn reset_onboarding(State(state): State<AppState>) -> impl IntoResponse {
    let next = CeremonyState { id: Uuid::now_v7(), completed: 0 };
    if let Some(store) = &state.store {
        if let Err(error) = store.ensure_ceremony(next.id, onboarding_template().len()).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "CEREMONY_RESET_FAILED", "developer_message": error.to_string() })),
            ).into_response();
        }
    }
    match state.ceremony.lock() {
        Ok(mut ceremony) => {
            *ceremony = next;
            (StatusCode::OK, Json(progress_from(&next))).into_response()
        }
        Err(_) => internal_error("CEREMONY_STATE_UNAVAILABLE"),
    }
}

async fn security_overview(State(state): State<AppState>, headers: HeaderMap) -> axum::response::Response {
    let session = match authorize_current_identity(&state, &headers, "can_read").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(evaluate(&GuardianSignals {
        strong_auth_credit: if session.trusted_device { 6 } else { 0 },
        ..GuardianSignals::default()
    })).into_response()
}

async fn evaluate_guardian(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut signals): Json<GuardianSignals>,
) -> axum::response::Response {
    let session = match authorize_current_identity(&state, &headers, "can_manage").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    // Authentication strength is a server-side fact. Never trust client-provided credit.
    signals.strong_auth_credit = if session.trusted_device { 6 } else { 0 };
    let decision = evaluate(&signals);
    if let Some(store) = &state.store {
        let correlation_id = Uuid::now_v7();
        if let Err(error) = store.record_guardian_decision(&decision, &signals, correlation_id).await {
            tracing::error!(%correlation_id, error = %error, "failed to persist Guardian decision");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "GUARDIAN_AUDIT_WRITE_FAILED", "correlation_id": correlation_id })),
            ).into_response();
        }
    }
    Json(decision).into_response()
}

async fn policy_status(State(state): State<AppState>) -> Json<PolicyStatus> {
    Json(PolicyStatus {
        configured: state.policy.is_some(),
        dev_bypass: state.policy_dev_bypass,
        mode: if state.policy.is_some() { "openfga" } else if state.policy_dev_bypass { "development-bypass" } else { "unavailable" },
    })
}

async fn bootstrap_self_policy(State(state): State<AppState>, headers: HeaderMap) -> axum::response::Response {
    let session = match resolve_session(&state, &headers).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let tuple = self_owner_tuple(session.identity_id);
    if let Some(policy) = &state.policy {
        if let Err(error) = policy.ensure_tuple(&tuple).await {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": "POLICY_PROVISION_FAILED", "developer_message": error.to_string() })),
            ).into_response();
        }
        return Json(SelfPolicyBootstrap {
            identity_ref: tuple.object,
            user_ref: tuple.user,
            relation: "owner",
            source: "openfga",
        }).into_response();
    }
    if state.policy_dev_bypass {
        return Json(SelfPolicyBootstrap {
            identity_ref: tuple.object,
            user_ref: tuple.user,
            relation: "owner",
            source: "development-bypass",
        }).into_response();
    }
    (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "POLICY_UNAVAILABLE" }))).into_response()
}

async fn policy_check(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(check): Json<PolicyCheck>,
) -> axum::response::Response {
    let session = match resolve_session(&state, &headers).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let expected_user = fga_user(session.identity_id);
    if check.user != expected_user {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "POLICY_CHECK_USER_MISMATCH" })),
        ).into_response();
    }
    if let Some(policy) = &state.policy {
        return match policy.check(&check).await {
            Ok(decision) => (StatusCode::OK, Json(decision)).into_response(),
            Err(error) => (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": "POLICY_UPSTREAM_FAILED", "developer_message": error.to_string() })),
            ).into_response(),
        };
    }
    if state.policy_dev_bypass {
        return (
            StatusCode::OK,
            Json(PolicyDecision { allowed: true, source: "development-bypass".into() }),
        ).into_response();
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "error": "POLICY_UNAVAILABLE" })),
    ).into_response()
}

async fn resolve_session(state: &AppState, headers: &HeaderMap) -> Result<ResolvedSession, axum::response::Response> {
    let Some(session_id) = session_id_from_headers(headers) else {
        return Err(unauthenticated_session());
    };

    if let Some(store) = &state.store {
        return match store.load_active_session(session_id).await {
            Ok(Some(session)) => Ok(ResolvedSession {
                session_id: session.id,
                identity_id: session.identity_id,
                subject: session.subject,
                display_name: session.display_name,
                auth_strength: session.auth_strength,
                trusted_device: session.trusted_device_id.is_some(),
            }),
            Ok(None) => Err(unauthenticated_session()),
            Err(error) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "SESSION_LOAD_FAILED", "developer_message": error.to_string() })),
            ).into_response()),
        };
    }

    let mut sessions = state.memory_sessions.lock().map_err(|_| internal_error("SESSION_STATE_UNAVAILABLE"))?;
    sessions.retain(|_, value| value.expires_at > Instant::now());
    match sessions.get(&session_id) {
        Some(session) => Ok(ResolvedSession {
            session_id,
            identity_id: session.identity_id,
            subject: session.subject.clone(),
            display_name: session.display_name.clone(),
            auth_strength: session.auth_strength.clone(),
            trusted_device: false,
        }),
        None => Err(unauthenticated_session()),
    }
}

async fn authorize_current_identity(
    state: &AppState,
    headers: &HeaderMap,
    relation: &str,
) -> Result<ResolvedSession, axum::response::Response> {
    let session = resolve_session(state, headers).await?;
    if let Some(policy) = &state.policy {
        let check = PolicyCheck {
            user: fga_user(session.identity_id),
            relation: relation.to_owned(),
            object: fga_identity(session.identity_id),
        };
        return match policy.check(&check).await {
            Ok(decision) if decision.allowed => Ok(session),
            Ok(_) => Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": "PERMISSION_DENIED", "relation": relation })),
            ).into_response()),
            Err(error) => Err((
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": "POLICY_UPSTREAM_FAILED", "developer_message": error.to_string() })),
            ).into_response()),
        };
    }
    if state.policy_dev_bypass {
        return Ok(session);
    }
    Err((StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "POLICY_UNAVAILABLE" }))).into_response())
}

fn self_owner_tuple(identity_id: Uuid) -> RelationshipTuple {
    RelationshipTuple {
        user: fga_user(identity_id),
        relation: "owner".into(),
        object: fga_identity(identity_id),
    }
}

fn fga_user(identity_id: Uuid) -> String {
    format!("user:{identity_id}")
}

fn fga_identity(identity_id: Uuid) -> String {
    format!("identity:{identity_id}")
}

fn session_id_from_headers(headers: &HeaderMap) -> Option<Uuid> {
    let cookie = headers.get(COOKIE)?.to_str().ok()?;
    cookie
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(name, value)| (name == SESSION_COOKIE).then(|| Uuid::parse_str(value).ok()).flatten())
}

fn build_session_cookie(session_id: Uuid, secure: bool, max_age: i64) -> String {
    format!(
        "{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

fn unauthenticated_session() -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(SessionSummary {
            authenticated: false,
            subject: None,
            display_name: None,
            auth_strength: None,
            trusted_device: false,
            online: true,
        }),
    ).into_response()
}

fn oidc_failure_redirect(state: &AppState, reason: &str) -> axum::response::Response {
    let target = format!("{}?authlink_login=error&authlink_reason={}#/auth", state.web_url, reason);
    let mut response = Redirect::to(&target).into_response();
    response.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn internal_error(code: &str) -> axum::response::Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": code }))).into_response()
}

async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "NOT_FOUND" })))
}
