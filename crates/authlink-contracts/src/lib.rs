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
