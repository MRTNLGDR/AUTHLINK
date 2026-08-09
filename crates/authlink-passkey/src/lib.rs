use authlink_store::AuthlinkStore;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use thiserror::Error;
use uuid::Uuid;

pub const PASSKEY_CHALLENGE_BYTES: usize = 32;
pub const PASSKEY_CHALLENGE_TTL_SECONDS: i64 = 120;

#[derive(Debug, Clone)]
pub struct PasskeyRepository {
    store: AuthlinkStore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredentialRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub identity_id: Uuid,
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub counter: u32,
    pub transports: Vec<String>,
    pub aaguid: Option<String>,
    pub attestation_format: Option<String>,
    pub credential_device_type: String,
    pub credential_backed_up: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredentialMetadata {
    pub id: Uuid,
    pub credential_id: String,
    pub transports: Vec<String>,
    pub credential_device_type: String,
    pub credential_backed_up: bool,
}

#[derive(Debug, Clone)]
pub struct PasskeyChallengeRecord {
    pub id: Uuid,
    pub challenge: Vec<u8>,
    pub action: String,
}

#[derive(Debug, Clone)]
pub struct NewPasskeyCredential<'a> {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub identity_id: Uuid,
    pub credential_id: &'a str,
    pub public_key: &'a [u8],
    pub counter: u32,
    pub transports: &'a [String],
    pub aaguid: Option<&'a str>,
    pub attestation_format: Option<&'a str>,
    pub credential_device_type: &'a str,
    pub credential_backed_up: bool,
}

#[derive(Debug, Error)]
pub enum PasskeyStoreError {
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("stored counter is outside WebAuthn u32 range: {0}")]
    CounterOutOfRange(i64),
}

impl PasskeyRepository {
    pub fn new(store: AuthlinkStore) -> Self {
        Self { store }
    }

    pub fn authlink_store(&self) -> &AuthlinkStore {
        &self.store
    }

    pub async fn create_challenge(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        identity_id: Uuid,
        session_id: Uuid,
        action: &str,
        challenge: &[u8],
        ttl_seconds: i64,
    ) -> Result<(), PasskeyStoreError> {
        sqlx::query(
            r#"
            insert into authlink.passkey_challenge
              (id, tenant_id, identity_id, session_id, action, challenge, expires_at)
            values ($1, $2, $3, $4, $5, $6, now() + ($7 * interval '1 second'))
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(identity_id)
        .bind(session_id)
        .bind(action)
        .bind(challenge)
        .bind(ttl_seconds)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn consume_challenge(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        identity_id: Uuid,
        session_id: Uuid,
        action: &str,
    ) -> Result<Option<PasskeyChallengeRecord>, PasskeyStoreError> {
        let row = sqlx::query(
            r#"
            update authlink.passkey_challenge
               set used_at = now()
             where id = $1 and tenant_id = $2 and identity_id = $3
               and session_id = $4 and action = $5
               and used_at is null and expires_at > now()
            returning id, challenge, action
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(identity_id)
        .bind(session_id)
        .bind(action)
        .fetch_optional(self.store.pool())
        .await?;
        Ok(row.map(|row| PasskeyChallengeRecord {
            id: row.get("id"),
            challenge: row.get("challenge"),
            action: row.get("action"),
        }))
    }

    pub async fn list_credentials(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<PasskeyCredentialMetadata>, PasskeyStoreError> {
        let rows = sqlx::query(
            r#"
            select id, credential_id, transports, credential_device_type, credential_backed_up
              from authlink.passkey_credential
             where tenant_id = $1 and identity_id = $2 and state = 'active'
             order by created_at desc
            "#,
        )
        .bind(tenant_id)
        .bind(identity_id)
        .fetch_all(self.store.pool())
        .await?;

        rows.into_iter()
            .map(|row| {
                let transports: serde_json::Value = row.try_get("transports")?;
                Ok(PasskeyCredentialMetadata {
                    id: row.try_get("id")?,
                    credential_id: row.try_get("credential_id")?,
                    transports: serde_json::from_value(transports)?,
                    credential_device_type: row.try_get("credential_device_type")?,
                    credential_backed_up: row.try_get("credential_backed_up")?,
                })
            })
            .collect()
    }

    pub async fn insert_credential(
        &self,
        credential: NewPasskeyCredential<'_>,
    ) -> Result<(), PasskeyStoreError> {
        sqlx::query(
            r#"
            insert into authlink.passkey_credential
              (id, tenant_id, identity_id, credential_id, public_key, counter, transports,
               aaguid, attestation_format, credential_device_type, credential_backed_up)
            values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
            "#,
        )
        .bind(credential.id)
        .bind(credential.tenant_id)
        .bind(credential.identity_id)
        .bind(credential.credential_id)
        .bind(credential.public_key)
        .bind(i64::from(credential.counter))
        .bind(serde_json::to_value(credential.transports)?)
        .bind(credential.aaguid)
        .bind(credential.attestation_format)
        .bind(credential.credential_device_type)
        .bind(credential.credential_backed_up)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }

    pub async fn load_credential(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        credential_id: &str,
    ) -> Result<Option<PasskeyCredentialRecord>, PasskeyStoreError> {
        let row = sqlx::query(
            r#"
            select id, tenant_id, identity_id, credential_id, public_key, counter, transports,
                   aaguid, attestation_format, credential_device_type, credential_backed_up
              from authlink.passkey_credential
             where tenant_id = $1 and identity_id = $2 and credential_id = $3
               and state = 'active' and revoked_at is null
            "#,
        )
        .bind(tenant_id)
        .bind(identity_id)
        .bind(credential_id)
        .fetch_optional(self.store.pool())
        .await?;

        row.map(|row| {
            let counter: i64 = row.try_get("counter")?;
            let counter = u32::try_from(counter).map_err(|_| PasskeyStoreError::CounterOutOfRange(counter))?;
            let transports: serde_json::Value = row.try_get("transports")?;
            Ok(PasskeyCredentialRecord {
                id: row.try_get("id")?,
                tenant_id: row.try_get("tenant_id")?,
                identity_id: row.try_get("identity_id")?,
                credential_id: row.try_get("credential_id")?,
                public_key: row.try_get("public_key")?,
                counter,
                transports: serde_json::from_value(transports)?,
                aaguid: row.try_get("aaguid")?,
                attestation_format: row.try_get("attestation_format")?,
                credential_device_type: row.try_get("credential_device_type")?,
                credential_backed_up: row.try_get("credential_backed_up")?,
            })
        })
        .transpose()
    }

    pub async fn update_counter(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        credential_id: &str,
        expected_counter: u32,
        new_counter: u32,
    ) -> Result<bool, PasskeyStoreError> {
        let result = sqlx::query(
            r#"
            update authlink.passkey_credential
               set counter = $5, last_used_at = now(), version = version + 1
             where tenant_id = $1 and identity_id = $2 and credential_id = $3
               and state = 'active' and revoked_at is null and counter = $4
            "#,
        )
        .bind(tenant_id)
        .bind(identity_id)
        .bind(credential_id)
        .bind(i64::from(expected_counter))
        .bind(i64::from(new_counter))
        .execute(self.store.pool())
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn mark_session_passkey_verified(
        &self,
        session_id: Uuid,
        tenant_id: Uuid,
        identity_id: Uuid,
        credential_id: &str,
        credential_device_type: &str,
        credential_backed_up: bool,
    ) -> Result<bool, PasskeyStoreError> {
        let result = sqlx::query(
            r#"
            update authlink.session
               set auth_strength = case
                     when trusted_device_id is not null then 'passkey+device-possession'
                     else 'passkey'
                   end,
                   assurance_evidence = coalesce(assurance_evidence, '{}'::jsonb)
                     || jsonb_build_object(
                          'webauthn',
                          jsonb_build_object(
                            'credential_id', $4,
                            'user_verified', true,
                            'credential_device_type', $5,
                            'credential_backed_up', $6,
                            'verified_at', now()
                          )
                        )
             where id = $1 and tenant_id = $2 and identity_id = $3
               and state = 'active' and revoked_at is null and expires_at > now()
            "#,
        )
        .bind(session_id)
        .bind(tenant_id)
        .bind(identity_id)
        .bind(credential_id)
        .bind(credential_device_type)
        .bind(credential_backed_up)
        .execute(self.store.pool())
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn revoke_credential(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        credential_id: &str,
    ) -> Result<bool, PasskeyStoreError> {
        let result = sqlx::query(
            r#"
            update authlink.passkey_credential
               set state = 'revoked', revoked_at = now(), version = version + 1
             where tenant_id = $1 and identity_id = $2 and credential_id = $3
               and state = 'active' and revoked_at is null
            "#,
        )
        .bind(tenant_id)
        .bind(identity_id)
        .bind(credential_id)
        .execute(self.store.pool())
        .await?;
        Ok(result.rows_affected() == 1)
    }
}
