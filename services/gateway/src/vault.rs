use super::{authorize_current_identity, AppState};
use authlink_store::VaultItemMetadata;
use authlink_vault::{KeyRing, VaultBinding, VaultError};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{env, sync::Arc};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub(crate) enum VaultServiceError {
    #[error("AUTHLINK_VAULT_ACTIVE_KEY_VERSION must be a positive integer")]
    InvalidActiveVersion,
    #[error(transparent)]
    Crypto(#[from] VaultError),
}

pub(crate) struct VaultService {
    keys: KeyRing,
}

impl VaultService {
    pub(crate) fn from_env() -> Result<Option<Arc<Self>>, VaultServiceError> {
        let encoded = match env::var("AUTHLINK_VAULT_KEYS") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => return Ok(None),
        };
        let active_version = env::var("AUTHLINK_VAULT_ACTIVE_KEY_VERSION")
            .map_err(|_| VaultServiceError::InvalidActiveVersion)?
            .parse::<u32>()
            .map_err(|_| VaultServiceError::InvalidActiveVersion)?;
        if active_version == 0 {
            return Err(VaultServiceError::InvalidActiveVersion);
        }
        Ok(Some(Arc::new(Self {
            keys: KeyRing::from_encoded(active_version, &encoded)?,
        })))
    }

    pub(crate) fn active_version(&self) -> u32 {
        self.keys.active_version()
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateVaultItemRequest {
    kind: String,
    purpose: String,
    payload: Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct VaultItemSummary {
    id: Uuid,
    kind: String,
    purpose: String,
    key_version: u32,
}

#[derive(Debug, Serialize)]
pub(crate) struct VaultItemResponse {
    id: Uuid,
    kind: String,
    purpose: String,
    key_version: u32,
    payload: Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct VaultListResponse {
    items: Vec<VaultItemSummary>,
}

#[derive(Debug, Serialize)]
pub(crate) struct VaultMutationResponse {
    id: Uuid,
    key_version: Option<u32>,
    state: &'static str,
}

pub(crate) async fn list_items(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let session = match authorize_current_identity(&state, &headers, "can_read").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let Some(store) = &state.store else {
        return unavailable("VAULT_DATABASE_REQUIRED");
    };
    if state.vault.is_none() {
        return unavailable("VAULT_KEYRING_UNAVAILABLE");
    }

    match store.list_vault_items(session.tenant_id, session.identity_id).await {
        Ok(items) => Json(VaultListResponse {
            items: items.into_iter().map(summary_from).collect(),
        })
        .into_response(),
        Err(error) => store_failure("VAULT_LIST_FAILED", error),
    }
}

pub(crate) async fn create_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateVaultItemRequest>,
) -> Response {
    let session = match authorize_current_identity(&state, &headers, "can_manage").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let Some(store) = &state.store else {
        return unavailable("VAULT_DATABASE_REQUIRED");
    };
    let Some(vault) = &state.vault else {
        return unavailable("VAULT_KEYRING_UNAVAILABLE");
    };

    if !valid_tag(&request.kind, 48) || !valid_tag(&request.purpose, 96) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": "VAULT_INVALID_KIND_OR_PURPOSE" })),
        )
            .into_response();
    }

    let plaintext = match serde_json::to_vec(&request.payload) {
        Ok(value) => Zeroizing::new(value),
        Err(_) => return internal("VAULT_SERIALIZATION_FAILED"),
    };
    if plaintext.len() > 1024 * 1024 {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "VAULT_ITEM_TOO_LARGE", "max_bytes": 1048576 })),
        )
            .into_response();
    }

    let id = Uuid::now_v7();
    let binding = VaultBinding::new(session.tenant_id, session.identity_id, id, request.purpose.clone());
    let envelope = match vault.keys.encrypt(&binding, plaintext.as_slice()) {
        Ok(envelope) => envelope,
        Err(error) => {
            tracing::error!(error = %error, %id, "vault encryption failed");
            return internal("VAULT_ENCRYPTION_FAILED");
        }
    };

    if let Err(error) = store
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
        return store_failure("VAULT_WRITE_FAILED", error);
    }

    (
        StatusCode::CREATED,
        Json(VaultItemSummary {
            id,
            kind: request.kind,
            purpose: request.purpose,
            key_version: envelope.key_version,
        }),
    )
        .into_response()
}

pub(crate) async fn get_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let session = match authorize_current_identity(&state, &headers, "can_read").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let Some(store) = &state.store else {
        return unavailable("VAULT_DATABASE_REQUIRED");
    };
    let Some(vault) = &state.vault else {
        return unavailable("VAULT_KEYRING_UNAVAILABLE");
    };

    let item = match store.load_vault_item(session.tenant_id, session.identity_id, id).await {
        Ok(Some(item)) => item,
        Ok(None) => return not_found(),
        Err(error) => return store_failure("VAULT_READ_FAILED", error),
    };
    let binding = VaultBinding::new(item.tenant_id, item.identity_id, item.id, item.purpose.clone());
    let plaintext = match vault.keys.decrypt(&binding, &item.envelope) {
        Ok(plaintext) => plaintext,
        Err(error) => {
            tracing::error!(error = %error, %id, key_version = item.key_version, "vault decryption failed");
            return internal("VAULT_DECRYPTION_FAILED");
        }
    };
    let payload: Value = match serde_json::from_slice(plaintext.as_slice()) {
        Ok(payload) => payload,
        Err(_) => return internal("VAULT_PAYLOAD_INVALID"),
    };

    Json(VaultItemResponse {
        id: item.id,
        kind: item.kind,
        purpose: item.purpose,
        key_version: item.key_version,
        payload,
    })
    .into_response()
}

pub(crate) async fn rotate_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let session = match authorize_current_identity(&state, &headers, "can_manage").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let Some(store) = &state.store else {
        return unavailable("VAULT_DATABASE_REQUIRED");
    };
    let Some(vault) = &state.vault else {
        return unavailable("VAULT_KEYRING_UNAVAILABLE");
    };

    let item = match store.load_vault_item(session.tenant_id, session.identity_id, id).await {
        Ok(Some(item)) => item,
        Ok(None) => return not_found(),
        Err(error) => return store_failure("VAULT_READ_FAILED", error),
    };
    if item.key_version == vault.active_version() {
        return Json(VaultMutationResponse {
            id,
            key_version: Some(item.key_version),
            state: "already-current",
        })
        .into_response();
    }

    let binding = VaultBinding::new(item.tenant_id, item.identity_id, item.id, item.purpose.clone());
    let rotated = match vault.keys.rewrap_to_active(&binding, &item.envelope) {
        Ok(rotated) => rotated,
        Err(error) => {
            tracing::error!(error = %error, %id, "vault key rewrap failed");
            return internal("VAULT_ROTATION_FAILED");
        }
    };
    match store
        .update_vault_envelope(
            session.tenant_id,
            session.identity_id,
            id,
            item.key_version,
            &rotated,
        )
        .await
    {
        Ok(true) => Json(VaultMutationResponse {
            id,
            key_version: Some(rotated.key_version),
            state: "rotated",
        })
        .into_response(),
        Ok(false) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "VAULT_ITEM_CHANGED" })),
        )
            .into_response(),
        Err(error) => store_failure("VAULT_ROTATION_WRITE_FAILED", error),
    }
}

pub(crate) async fn delete_item(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let session = match authorize_current_identity(&state, &headers, "can_manage").await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let Some(store) = &state.store else {
        return unavailable("VAULT_DATABASE_REQUIRED");
    };
    if state.vault.is_none() {
        return unavailable("VAULT_KEYRING_UNAVAILABLE");
    }

    match store.delete_vault_item(session.tenant_id, session.identity_id, id).await {
        Ok(true) => Json(VaultMutationResponse {
            id,
            key_version: None,
            state: "deleted",
        })
        .into_response(),
        Ok(false) => not_found(),
        Err(error) => store_failure("VAULT_DELETE_FAILED", error),
    }
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
    let len = value.len();
    len > 0
        && len <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' ))
}

fn unavailable(code: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "error": code })),
    )
        .into_response()
}

fn internal(code: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": code })),
    )
        .into_response()
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "VAULT_ITEM_NOT_FOUND" })),
    )
        .into_response()
}

fn store_failure(code: &str, error: impl std::fmt::Display) -> Response {
    let correlation_id = Uuid::now_v7();
    tracing::error!(%correlation_id, error = %error, "vault persistence operation failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": code, "correlation_id": correlation_id })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_restricted_to_safe_identifiers() {
        assert!(valid_tag("credential.password", 48));
        assert!(valid_tag("credential:store", 96));
        assert!(!valid_tag("password for bank", 48));
        assert!(!valid_tag("", 48));
    }
}
