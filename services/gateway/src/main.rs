use authlink_contracts::{
    AdvanceOnboardingRequest, AdvanceOnboardingResponse, AuthStrength, Capability, GuardianDecision,
    GuardianSignals, OnboardingProgress, OnboardingStep, OnboardingStepId, StepStatus,
};
use authlink_guardian::evaluate;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use std::{net::SocketAddr, sync::{Arc, Mutex}};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;

#[derive(Debug)]
struct CeremonyState {
    id: Uuid,
    completed: usize,
}

#[derive(Clone)]
struct AppState {
    capabilities: Arc<Vec<Capability>>,
    ceremony: Arc<Mutex<CeremonyState>>,
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
        cap("identity.onboarding", "Cerimônia de identidade", "identity"),
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
        ceremony: Arc::new(Mutex::new(CeremonyState {
            id: Uuid::now_v7(),
            completed: 0,
        })),
    };

    let app = Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/authlink/capabilities", get(list_capabilities))
        .route("/api/v1/authlink/session", get(session))
        .route("/api/v1/authlink/onboarding", get(get_onboarding))
        .route("/api/v1/authlink/onboarding/advance", post(advance_onboarding))
        .route("/api/v1/authlink/onboarding/reset", post(reset_onboarding))
        .route("/api/v1/authlink/security/overview", get(security_overview))
        .route("/api/v1/authlink/security/evaluate", post(evaluate_guardian))
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
        auth_strength: if completed > passkey_index {
            AuthStrength::PasskeyDevice
        } else {
            AuthStrength::Anonymous
        },
        trusted_device: completed > device_index,
        risk_score: if completed > device_index { 8 } else { 24 },
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

async fn get_onboarding(State(state): State<AppState>) -> impl IntoResponse {
    match state.ceremony.lock() {
        Ok(ceremony) => (StatusCode::OK, Json(progress_from(&ceremony))).into_response(),
        Err(_) => internal_error("CEREMONY_STATE_UNAVAILABLE"),
    }
}

async fn advance_onboarding(
    State(state): State<AppState>,
    Json(request): Json<AdvanceOnboardingRequest>,
) -> impl IntoResponse {
    let mut ceremony = match state.ceremony.lock() {
        Ok(value) => value,
        Err(_) => return internal_error("CEREMONY_STATE_UNAVAILABLE"),
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
        )
            .into_response();
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
        )
            .into_response();
    }

    if request.skip && expected.3 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(AdvanceOnboardingResponse {
                accepted: false,
                progress: progress_from(&ceremony),
                message: Some("Esta etapa é obrigatória".into()),
            }),
        )
            .into_response();
    }

    ceremony.completed += 1;
    (
        StatusCode::OK,
        Json(AdvanceOnboardingResponse {
            accepted: true,
            progress: progress_from(&ceremony),
            message: request.evidence_ref.map(|_| "Evidência referenciada com sucesso".into()),
        }),
    )
        .into_response()
}

async fn reset_onboarding(State(state): State<AppState>) -> impl IntoResponse {
    match state.ceremony.lock() {
        Ok(mut ceremony) => {
            ceremony.id = Uuid::now_v7();
            ceremony.completed = 0;
            (StatusCode::OK, Json(progress_from(&ceremony))).into_response()
        }
        Err(_) => internal_error("CEREMONY_STATE_UNAVAILABLE"),
    }
}

async fn security_overview() -> Json<GuardianDecision> {
    Json(evaluate(&GuardianSignals {
        strong_auth_credit: 6,
        ..GuardianSignals::default()
    }))
}

async fn evaluate_guardian(Json(signals): Json<GuardianSignals>) -> Json<GuardianDecision> {
    Json(evaluate(&signals))
}

fn internal_error(code: &str) -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": code })),
    )
        .into_response()
}

async fn not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "NOT_FOUND" })),
    )
}
