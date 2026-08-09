use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
    pub session_id: Uuid,
    pub app_id: String,
    pub purpose: String,
    pub correlation_id: Uuid,
    pub auth_strength: AuthStrength,
    pub offline: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthStrength {
    Anonymous,
    Password,
    Passkey,
    PasskeyDevice,
    StepUp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub id: String,
    pub title: String,
    pub group: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEnvelope {
    pub event_id: Uuid,
    pub actor_id: Uuid,
    pub object_ref: String,
    pub purpose: String,
    pub correlation_id: Uuid,
    pub occurred_at: OffsetDateTime,
    pub outcome: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OnboardingStepId {
    Welcome,
    Account,
    DeviceIntegrity,
    FaceCapture,
    Liveness,
    Document,
    IdentityMatch,
    Consent,
    Passkey,
    SecondFactor,
    Recovery,
    VaultSetup,
    SovereignIdentity,
    AvatarOptIn,
    AuditProof,
    Complete,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum StepStatus {
    Pending,
    Active,
    Complete,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardingStep {
    pub id: OnboardingStepId,
    pub title: String,
    pub subtitle: String,
    pub status: StepStatus,
    pub required: bool,
    pub purpose: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardingProgress {
    pub ceremony_id: Uuid,
    pub current_index: usize,
    pub completed: usize,
    pub total: usize,
    pub steps: Vec<OnboardingStep>,
    pub auth_strength: AuthStrength,
    pub trusted_device: bool,
    pub risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvanceOnboardingRequest {
    pub step: OnboardingStepId,
    #[serde(default)]
    pub evidence_ref: Option<String>,
    #[serde(default)]
    pub skip: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvanceOnboardingResponse {
    pub accepted: bool,
    pub progress: OnboardingProgress,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GuardianSignals {
    pub device_integrity_penalty: u8,
    pub network_penalty: u8,
    pub credential_exposure_penalty: u8,
    pub session_context_penalty: u8,
    pub anomaly_penalty: u8,
    pub strong_auth_credit: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianDecision {
    pub score: u8,
    pub level: RiskLevel,
    pub action: String,
    pub reasons: Vec<String>,
    pub requires_step_up: bool,
}
