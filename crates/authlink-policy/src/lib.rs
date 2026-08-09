use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct OpenFgaConfig {
    pub api_url: String,
    pub store_id: String,
    pub authorization_model_id: Option<String>,
    pub api_token: Option<String>,
}

impl OpenFgaConfig {
    pub fn from_env() -> Result<Option<Self>, PolicyError> {
        let api_url = match env::var("OPENFGA_API_URL") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => return Ok(None),
        };
        let store_id = env::var("OPENFGA_STORE_ID")
            .map_err(|_| PolicyError::Configuration("OPENFGA_STORE_ID is required when OPENFGA_API_URL is set".into()))?;
        if store_id.trim().is_empty() {
            return Err(PolicyError::Configuration("OPENFGA_STORE_ID cannot be empty".into()));
        }
        Ok(Some(Self {
            api_url: api_url.trim_end_matches('/').to_owned(),
            store_id,
            authorization_model_id: env::var("OPENFGA_AUTHORIZATION_MODEL_ID").ok().filter(|v| !v.trim().is_empty()),
            api_token: env::var("OPENFGA_API_TOKEN").ok().filter(|v| !v.trim().is_empty()),
        }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCheck {
    pub user: String,
    pub relation: String,
    pub object: String,
}

impl PolicyCheck {
    pub fn validate(&self) -> Result<(), PolicyError> {
        for (name, value) in [("user", &self.user), ("relation", &self.relation), ("object", &self.object)] {
            if value.trim().is_empty() {
                return Err(PolicyError::InvalidCheck(format!("{name} cannot be empty")));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub source: String,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy configuration error: {0}")]
    Configuration(String),
    #[error("invalid authorization check: {0}")]
    InvalidCheck(String),
    #[error("OpenFGA request failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("OpenFGA returned HTTP {status}: {body}")]
    Upstream { status: StatusCode, body: String },
    #[error("OpenFGA response did not include allowed")]
    InvalidResponse,
}

#[derive(Clone)]
pub struct OpenFgaClient {
    config: OpenFgaConfig,
    http: reqwest::Client,
}

impl OpenFgaClient {
    pub fn new(config: OpenFgaConfig) -> Self {
        Self { config, http: reqwest::Client::new() }
    }

    pub fn from_env() -> Result<Option<Self>, PolicyError> {
        Ok(OpenFgaConfig::from_env()?.map(Self::new))
    }

    pub fn endpoint(&self) -> String {
        format!("{}/stores/{}/check", self.config.api_url, self.config.store_id)
    }

    pub async fn check(&self, check: &PolicyCheck) -> Result<PolicyDecision, PolicyError> {
        check.validate()?;
        let body = check_payload(check, self.config.authorization_model_id.as_deref());
        let mut request = self.http.post(self.endpoint()).json(&body);
        if let Some(token) = &self.config.api_token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_else(|_| "<unreadable>".into());
            return Err(PolicyError::Upstream { status, body });
        }
        let body: Value = response.json().await?;
        let allowed = body.get("allowed").and_then(Value::as_bool).ok_or(PolicyError::InvalidResponse)?;
        Ok(PolicyDecision { allowed, source: "openfga".into() })
    }
}

pub fn check_payload(check: &PolicyCheck, model_id: Option<&str>) -> Value {
    let mut body = json!({
        "tuple_key": {
            "user": check.user,
            "relation": check.relation,
            "object": check.object
        }
    });
    if let Some(model_id) = model_id {
        body["authorization_model_id"] = Value::String(model_id.to_owned());
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_matches_openfga_check_contract() {
        let body = check_payload(
            &PolicyCheck { user: "user:019".into(), relation: "viewer".into(), object: "authlink:identity:019".into() },
            Some("01MODEL"),
        );
        assert_eq!(body["authorization_model_id"], "01MODEL");
        assert_eq!(body["tuple_key"]["user"], "user:019");
        assert_eq!(body["tuple_key"]["relation"], "viewer");
        assert_eq!(body["tuple_key"]["object"], "authlink:identity:019");
    }

    #[test]
    fn validation_rejects_empty_tuple_parts() {
        let result = PolicyCheck { user: String::new(), relation: "viewer".into(), object: "identity:1".into() }.validate();
        assert!(matches!(result, Err(PolicyError::InvalidCheck(_))));
    }
}
