use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct IdpConfig {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

impl IdpConfig {
    pub fn from_env() -> Result<Option<Self>, IdpError> {
        let issuer = match env::var("AUTHLINK_OIDC_ISSUER") {
            Ok(value) if !value.trim().is_empty() => value.trim_end_matches('/').to_owned(),
            _ => return Ok(None),
        };
        let client_id = env::var("AUTHLINK_OIDC_CLIENT_ID")
            .map_err(|_| IdpError::Configuration("AUTHLINK_OIDC_CLIENT_ID is required when issuer is configured".into()))?;
        let redirect_uri = env::var("AUTHLINK_OIDC_REDIRECT_URI")
            .unwrap_or_else(|_| "http://127.0.0.1:8787/api/v1/authlink/oidc/callback".into());
        let scopes = env::var("AUTHLINK_OIDC_SCOPES")
            .unwrap_or_else(|_| "openid profile email".into())
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        Ok(Some(Self { issuer, client_id, redirect_uri, scopes }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicOidcStatus {
    pub configured: bool,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub discovery_ready: bool,
    pub pkce_s256: bool,
}

#[derive(Debug, Clone)]
pub struct PkceTransaction {
    pub authorization_url: String,
    pub state: String,
    pub code_verifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
}

#[derive(Debug, Error)]
pub enum IdpError {
    #[error("OIDC configuration error: {0}")]
    Configuration(String),
    #[error("invalid OIDC URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("OIDC network error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("OIDC upstream returned HTTP {status}: {body}")]
    Upstream { status: StatusCode, body: String },
    #[error("OIDC provider does not expose a userinfo endpoint")]
    UserInfoUnavailable,
    #[error("OIDC provider does not advertise PKCE S256")]
    PkceS256Required,
}

#[derive(Clone)]
pub struct OidcClient {
    config: IdpConfig,
    http: reqwest::Client,
}

impl OidcClient {
    pub fn new(config: IdpConfig) -> Self {
        Self { config, http: reqwest::Client::new() }
    }

    pub fn from_env() -> Result<Option<Self>, IdpError> {
        Ok(IdpConfig::from_env()?.map(Self::new))
    }

    pub fn config(&self) -> &IdpConfig {
        &self.config
    }

    pub async fn discover(&self) -> Result<OidcMetadata, IdpError> {
        let url = format!("{}/.well-known/openid-configuration", self.config.issuer);
        let response = self.http.get(url).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(IdpError::Upstream { status, body: response.text().await.unwrap_or_default() });
        }
        let metadata: OidcMetadata = response.json().await?;
        if metadata.issuer.trim_end_matches('/') != self.config.issuer.trim_end_matches('/') {
            return Err(IdpError::Configuration("discovery issuer does not match AUTHLINK_OIDC_ISSUER".into()));
        }
        Ok(metadata)
    }

    pub fn begin_authorization(&self, metadata: &OidcMetadata) -> Result<PkceTransaction, IdpError> {
        if !metadata.code_challenge_methods_supported.iter().any(|method| method == "S256") {
            return Err(IdpError::PkceS256Required);
        }
        let code_verifier = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let state = Uuid::new_v4().simple().to_string();
        let mut url = Url::parse(&metadata.authorization_endpoint)?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("response_type", "code");
            query.append_pair("client_id", &self.config.client_id);
            query.append_pair("redirect_uri", &self.config.redirect_uri);
            query.append_pair("scope", &self.config.scopes.join(" "));
            query.append_pair("state", &state);
            query.append_pair("code_challenge", &code_challenge);
            query.append_pair("code_challenge_method", "S256");
        }
        Ok(PkceTransaction { authorization_url: url.to_string(), state, code_verifier })
    }

    pub async fn exchange_code(
        &self,
        metadata: &OidcMetadata,
        code: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, IdpError> {
        let form = [
            ("grant_type", "authorization_code"),
            ("client_id", self.config.client_id.as_str()),
            ("redirect_uri", self.config.redirect_uri.as_str()),
            ("code", code),
            ("code_verifier", code_verifier),
        ];
        let response = self.http.post(&metadata.token_endpoint).form(&form).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(IdpError::Upstream { status, body: response.text().await.unwrap_or_default() });
        }
        Ok(response.json().await?)
    }

    pub async fn userinfo(&self, metadata: &OidcMetadata, access_token: &str) -> Result<UserInfo, IdpError> {
        let endpoint = metadata.userinfo_endpoint.as_ref().ok_or(IdpError::UserInfoUnavailable)?;
        let response = self.http.get(endpoint).bearer_auth(access_token).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(IdpError::Upstream { status, body: response.text().await.unwrap_or_default() });
        }
        Ok(response.json().await?)
    }

    pub fn public_status(&self, metadata: Option<&OidcMetadata>) -> PublicOidcStatus {
        PublicOidcStatus {
            configured: true,
            issuer: Some(self.config.issuer.clone()),
            client_id: Some(self.config.client_id.clone()),
            redirect_uri: Some(self.config.redirect_uri.clone()),
            discovery_ready: metadata.is_some(),
            pkce_s256: metadata.map(|m| m.code_challenge_methods_supported.iter().any(|method| method == "S256")).unwrap_or(false),
        }
    }
}

pub fn unconfigured_status() -> PublicOidcStatus {
    PublicOidcStatus {
        configured: false,
        issuer: None,
        client_id: None,
        redirect_uri: None,
        discovery_ready: false,
        pkce_s256: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> OidcClient {
        OidcClient::new(IdpConfig {
            issuer: "https://id.example".into(),
            client_id: "authlink".into(),
            redirect_uri: "https://app.example/callback".into(),
            scopes: vec!["openid".into(), "profile".into()],
        })
    }

    fn metadata() -> OidcMetadata {
        OidcMetadata {
            issuer: "https://id.example".into(),
            authorization_endpoint: "https://id.example/authorize".into(),
            token_endpoint: "https://id.example/token".into(),
            jwks_uri: "https://id.example/jwks".into(),
            userinfo_endpoint: Some("https://id.example/userinfo".into()),
            end_session_endpoint: None,
            code_challenge_methods_supported: vec!["S256".into()],
        }
    }

    #[test]
    fn pkce_authorization_request_contains_required_parameters() {
        let tx = client().begin_authorization(&metadata()).expect("create PKCE transaction");
        let url = Url::parse(&tx.authorization_url).unwrap();
        let pairs: std::collections::HashMap<_,_> = url.query_pairs().into_owned().collect();
        assert_eq!(pairs.get("response_type").map(String::as_str), Some("code"));
        assert_eq!(pairs.get("client_id").map(String::as_str), Some("authlink"));
        assert_eq!(pairs.get("code_challenge_method").map(String::as_str), Some("S256"));
        assert!(pairs.get("code_challenge").is_some_and(|v| !v.is_empty()));
        assert_eq!(tx.code_verifier.len(), 64);
        assert!(!tx.state.is_empty());
    }

    #[test]
    fn refuses_provider_without_s256() {
        let mut meta = metadata();
        meta.code_challenge_methods_supported.clear();
        assert!(matches!(client().begin_authorization(&meta), Err(IdpError::PkceS256Required)));
    }
}
