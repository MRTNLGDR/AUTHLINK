use authlink_contracts::{
    AdvanceOnboardingRequest, AdvanceOnboardingResponse, AuthStrength, Capability, GuardianDecision,
    GuardianSignals, OnboardingProgress, OnboardingStep, OnboardingStepId, StepStatus,
};
use authlink_guardian::evaluate;
use authlink_policy::{OpenFgaClient, PolicyCheck, PolicyDecision};
use authlink_store::AuthlinkStore;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use std::{env, net::SocketAddr, sync::{Arc, Mutex}};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
struct CeremonyState {
    id: Uuid,
    completed: usize,
}

#[derive(Clone)]
struct AppState {
    capabilities: Arc<Vec<Capability>>,
    ceremony: Arc<Mutex<CeremonyState>>,
    store: Option<AuthlinkStore>,
    policy: Option<OpenFgaClient>,
    policy_dev_bypass: bool,
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

#[derive(Serialize)]
struct PolicyStatus {
    configured: bool,
    dev_bypass: bool,
    mode: &'static str,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    let environment = env::var("AUTHLINK_ENV").unwrap_or_else(|_| "development".into());
    let is_production = environment.eq_ignore_ascii_case("production");

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
            tracing::warn!(error = %error, "PostgreSQL unavailable; using development in-memory ceremony store");
            None
        }
    };
    if is_production && store.is_none() {
        panic!("DATABASE_URL is mandatory in production");
    }

    let initial_ceremony = CeremonyState { id: Uuid::now_v7(), completed: 0 };
    if let Some(database) = &store {
        database
            .ensure_ceremony(initial_ceremony.id, onboarding_template().len())
            .await
            .expect("authlink migrations must be applied before gateway startup");
    }

    let capabilities = vec![
        cap("identity.sso", "SSO & Passkeys", "identity"),
        cap("identity.onboarding", "Cerimônia de identidade", "identity"),
        cap("authorization.openfga", "OpenFGA ReBAC", "identity"),
        cap("persistence.postgres", "PostgreSQL authority", "platform"),
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
    };

    let app = Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/authlink/runtime", get(runtime_status))
        .route("/api/v1/authlink/capabilities", get(list_capabilities))
        .route("/api/v1/authlink/session", get(session))
        .route("/api/v1/authlink/onboarding", get(get_onboarding))
        .route("/api/v1/authlink/onboarding/advance", post(advance_onboarding))
        .route("/api/v1/authlink/onboarding/reset", post(reset_onboarding))
        .route("/api/v1/authlink/security/overview", get(security_overview))
        .route("/api/v1/authlink/security/evaluate", post(evaluate_guardian))
        .route("/api/v1/authlink/policy/status", get(policy_status))
        .route("/api/v1/authlink/policy/check", post(policy_check))
        .route("/api/v1/capabilities/authlink", get(list_capabilities))
        .fallback(not_found)
        .with_state(state)
        .layer(CorsLayer::permissive())
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
        (OnboardingStepId::DeviceIntegrity, "Integridade do dispositivo", "Validamos postura, integridade e sinais do dispositivo.", true, "device.trust"),
        (OnboardingStepId::FaceCapture, "Captura facial", "Mapeamento facial para proofing e referência PERZON autorizada.", true, "biometric.enroll"),
        (OnboardingStepId::Liveness, "Prova de vida", "PAD/liveness confirma presença real sem manter vídeo bruto por padrão.", true, "biometric.liveness"),
        (OnboardingStepId::Document, "Documento oficial", "OCR e validação documental quando a finalidade exigir.", false, "identity.document"),
        (OnboardingStepId::IdentityMatch, "Correspondência de identidade", "Combinamos evidências e elevamos revisão quando o risco pede.", true, "identity.match"),
        (OnboardingStepId::Consent, "Consentimentos", "Você escolhe finalidade, escopo, retenção e uso de cada dado sensível.", true, "consent.grant"),
        (OnboardingStepId::Passkey, "Cadastrar passkey", "A passkey protegida pelo sistema operacional vira o fator principal.", true, "credential.passkey"),
        (OnboardingStepId::SecondFactor, "Segundo fator", "Adicione security key ou método alternativo de recuperação forte.", false, "credential.second-factor"),
        (OnboardingStepId::Recovery, "Recuperação", "Gere códigos e configure contatos confiáveis sem criar backdoor.", true, "identity.recovery"),
        (OnboardingStepId::VaultSetup, "Configurar Vault", "Crie o cofre local e a hierarquia de chaves para credenciais e mídia.", true, "vault.bootstrap"),
        (OnboardingStepId::SovereignIdentity, "Identidade soberana", "Revise credenciais, dispositivos, scopes e trust score.", true, "identity.activate"),
        (OnboardingStepId::AvatarOptIn, "Referência para avatar PEZON", "Opcional: autorize uma referência separada para seu gêmeo digital.", false, "avatar.reference"),
        (OnboardingStepId::AuditProof, "Prova e auditoria", "Registramos o resultado mínimo da cerimônia e a trilha de consentimento.", true, "audit.write"),
        (OnboardingStepId::Complete, "Acesso liberado", "Sua identidade está pronta. O AuthLink abre diretamente no Feed.", true, "session.activate"),
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

    let passkey_index = 8;
    let device_index = 2;
    OnboardingProgress {
        ceremony_id: state.id,
        current_index: completed.min(total.saturating_sub(1)),
        completed,
        total,
        steps,
        auth_strength: if completed > passkey_index { AuthStrength::PasskeyDevice } else { AuthStrength::Anonymous },
        trusted_device: completed > device_index,
        risk_score: if completed > device_index { 8 } else { 24 },
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
    })
}

async fn list_capabilities(State(state): State<AppState>) -> Json<CapabilityResponse> {
    Json(CapabilityResponse { capabilities: (*state.capabilities).clone() })
}

async fn session() -> Json<SessionSummary<'static>> {
    Json(SessionSummary { subject: "local-user", auth_strength: "passkey+device", trusted_device: true, online: true })
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

async fn security_overview() -> Json<GuardianDecision> {
    Json(evaluate(&GuardianSignals { strong_auth_credit: 6, ..GuardianSignals::default() }))
}

async fn evaluate_guardian(State(state): State<AppState>, Json(signals): Json<GuardianSignals>) -> Json<GuardianDecision> {
    let decision = evaluate(&signals);
    if let Some(store) = &state.store {
        let correlation_id = Uuid::now_v7();
        if let Err(error) = store.record_guardian_decision(&decision, &signals, correlation_id).await {
            tracing::error!(%correlation_id, error = %error, "failed to persist Guardian decision");
        }
    }
    Json(decision)
}

async fn policy_status(State(state): State<AppState>) -> Json<PolicyStatus> {
    Json(PolicyStatus {
        configured: state.policy.is_some(),
        dev_bypass: state.policy_dev_bypass,
        mode: if state.policy.is_some() { "openfga" } else if state.policy_dev_bypass { "development-bypass" } else { "unavailable" },
    })
}

async fn policy_check(State(state): State<AppState>, Json(check): Json<PolicyCheck>) -> impl IntoResponse {
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

fn internal_error(code: &str) -> axum::response::Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": code }))).into_response()
}

async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "NOT_FOUND" })))
}
