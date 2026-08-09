use authlink_contracts::{GuardianDecision, GuardianSignals};
use authlink_vault::EncryptedEnvelope;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::env;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub struct CeremonyRecord {
    pub id: Uuid,
    pub completed_steps: usize,
}

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub id: Uuid,
    pub identity_id: Uuid,
    pub tenant_id: Uuid,
    pub subject: String,
    pub display_name: Option<String>,
    pub auth_strength: String,
    pub purpose: String,
    pub audience: String,
    pub trusted_device_id: Option<Uuid>,
    pub assurance_evidence: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct DeviceChallengeRecord {
    pub id: Uuid,
    pub device_id: Option<Uuid>,
    pub nonce: Vec<u8>,
    pub action: String,
}

#[derive(Debug, Clone)]
pub struct TrustedDeviceRecord {
    pub id: Uuid,
    pub device_public_id: String,
    pub platform: String,
    pub display_name: Option<String>,
    pub trust_state: String,
    pub key_alg: Option<String>,
    pub public_key_jwk: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct TrustedDeviceMetadata {
    pub id: Uuid,
    pub device_public_id: String,
    pub platform: String,
    pub display_name: Option<String>,
    pub trust_state: String,
    pub key_alg: Option<String>,
    pub last_seen_at: Option<time::OffsetDateTime>,
}

#[derive(Debug, Clone)]
pub struct VaultItemRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub identity_id: Uuid,
    pub kind: String,
    pub purpose: String,
    pub key_version: u32,
    pub envelope: EncryptedEnvelope,
}

#[derive(Debug, Clone)]
pub struct VaultItemMetadata {
    pub id: Uuid,
    pub kind: String,
    pub purpose: String,
    pub key_version: u32,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid stored integer value for {0}")]
    InvalidInteger(&'static str),
}

#[derive(Clone)]
pub struct AuthlinkStore {
    pool: PgPool,
}

impl AuthlinkStore {
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .min_connections(1)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    pub async fn from_env() -> Result<Option<Self>, StoreError> {
        match env::var("DATABASE_URL") {
            Ok(url) if !url.trim().is_empty() => Self::connect(&url).await.map(Some),
            _ => Ok(None),
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn ensure_ceremony(&self, id: Uuid, total_steps: usize) -> Result<CeremonyRecord, StoreError> {
        let total_steps = i32::try_from(total_steps).map_err(|_| StoreError::InvalidInteger("total_steps"))?;
        sqlx::query(
            r#"
            insert into authlink.onboarding_ceremony
              (id, current_step, completed_steps, total_steps, auth_strength, trusted_device, risk_score, state)
            values ($1, 'welcome', 0, $2, 'anonymous', false, 24, 'active')
            on conflict (id) do nothing
            "#,
        )
        .bind(id)
        .bind(total_steps)
        .execute(&self.pool)
        .await?;
        self.load_ceremony(id).await
    }

    pub async fn load_ceremony(&self, id: Uuid) -> Result<CeremonyRecord, StoreError> {
        let row = sqlx::query("select id, completed_steps from authlink.onboarding_ceremony where id = $1")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        let completed: i32 = row.try_get("completed_steps")?;
        Ok(CeremonyRecord {
            id: row.try_get("id")?,
            completed_steps: usize::try_from(completed).map_err(|_| StoreError::InvalidInteger("completed_steps"))?,
        })
    }

    pub async fn advance_ceremony(
        &self,
        id: Uuid,
        expected_completed: usize,
        new_completed: usize,
        current_step: &str,
        auth_strength: &str,
        trusted_device: bool,
        risk_score: u8,
        complete: bool,
    ) -> Result<bool, StoreError> {
        let expected_completed = i32::try_from(expected_completed).map_err(|_| StoreError::InvalidInteger("expected_completed"))?;
        let new_completed = i32::try_from(new_completed).map_err(|_| StoreError::InvalidInteger("new_completed"))?;
        let result = sqlx::query(
            r#"
            update authlink.onboarding_ceremony
               set completed_steps = $3,
                   current_step = $4,
                   auth_strength = $5,
                   trusted_device = $6,
                   risk_score = $7,
                   state = case when $8 then 'complete' else 'active' end,
                   completed_at = case when $8 then now() else completed_at end,
                   updated_at = now()
             where id = $1 and completed_steps = $2
            "#,
        )
        .bind(id)
        .bind(expected_completed)
        .bind(new_completed)
        .bind(current_step)
        .bind(auth_strength)
        .bind(trusted_device)
        .bind(i16::from(risk_score))
        .bind(complete)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn upsert_oidc_identity(
        &self,
        tenant_id: Uuid,
        subject: &str,
        display_name: Option<&str>,
    ) -> Result<Uuid, StoreError> {
        let identity_id: Uuid = sqlx::query_scalar(
            r#"
            insert into authlink.identity (tenant_id, subject, display_name, assurance_level)
            values ($1, $2, $3, 'oidc')
            on conflict (subject) do update
               set display_name = coalesce(excluded.display_name, authlink.identity.display_name),
                   updated_at = now(),
                   version = authlink.identity.version + 1
            returning id
            "#,
        )
        .bind(tenant_id)
        .bind(subject)
        .bind(display_name)
        .fetch_one(&self.pool)
        .await?;
        Ok(identity_id)
    }

    pub async fn create_session(
        &self,
        session_id: Uuid,
        tenant_id: Uuid,
        identity_id: Uuid,
        audience: &str,
        purpose: &str,
        auth_strength: &str,
        ttl_seconds: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            insert into authlink.session
              (id, tenant_id, identity_id, audience, purpose, auth_strength, state, expires_at)
            values ($1, $2, $3, $4, $5, $6, 'active', now() + ($7 * interval '1 second'))
            "#,
        )
        .bind(session_id)
        .bind(tenant_id)
        .bind(identity_id)
        .bind(audience)
        .bind(purpose)
        .bind(auth_strength)
        .bind(ttl_seconds)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn load_active_session(&self, session_id: Uuid) -> Result<Option<SessionRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            select s.id, s.identity_id, s.tenant_id, i.subject, i.display_name,
                   s.auth_strength, s.purpose, s.audience, s.trusted_device_id,
                   s.assurance_evidence
              from authlink.session s
              join authlink.identity i on i.id = s.identity_id
             where s.id = $1
               and s.state = 'active'
               and s.revoked_at is null
               and s.expires_at > now()
            "#,
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| SessionRecord {
            id: row.get("id"),
            identity_id: row.get("identity_id"),
            tenant_id: row.get("tenant_id"),
            subject: row.get("subject"),
            display_name: row.get("display_name"),
            auth_strength: row.get("auth_strength"),
            purpose: row.get("purpose"),
            audience: row.get("audience"),
            trusted_device_id: row.get("trusted_device_id"),
            assurance_evidence: row.get("assurance_evidence"),
        }))
    }

    pub async fn revoke_session(&self, session_id: Uuid) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "update authlink.session set state = 'revoked', revoked_at = now() where id = $1 and state = 'active'",
        )
        .bind(session_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn create_device_challenge(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        identity_id: Uuid,
        session_id: Uuid,
        device_id: Option<Uuid>,
        action: &str,
        nonce: &[u8],
        ttl_seconds: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            insert into authlink.device_challenge
              (id, tenant_id, identity_id, session_id, device_id, action, nonce, expires_at)
            values ($1, $2, $3, $4, $5, $6, $7, now() + ($8 * interval '1 second'))
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(identity_id)
        .bind(session_id)
        .bind(device_id)
        .bind(action)
        .bind(nonce)
        .bind(ttl_seconds)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn consume_device_challenge(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        identity_id: Uuid,
        session_id: Uuid,
        action: &str,
    ) -> Result<Option<DeviceChallengeRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            update authlink.device_challenge
               set used_at = now()
             where id = $1 and tenant_id = $2 and identity_id = $3
               and session_id = $4 and action = $5
               and used_at is null and expires_at > now()
            returning id, device_id, nonce, action
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(identity_id)
        .bind(session_id)
        .bind(action)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| DeviceChallengeRecord {
            id: row.get("id"),
            device_id: row.get("device_id"),
            nonce: row.get("nonce"),
            action: row.get("action"),
        }))
    }

    pub async fn upsert_unrevoked_device(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        identity_id: Uuid,
        device_public_id: &str,
        platform: &str,
        display_name: Option<&str>,
        key_alg: &str,
        public_key_jwk: &serde_json::Value,
    ) -> Result<Option<TrustedDeviceRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            insert into authlink.trusted_device
              (id, tenant_id, identity_id, device_public_id, platform, trust_state,
               attestation_kind, display_name, key_alg, public_key_jwk, last_seen_at)
            values ($1, $2, $3, $4, $5, 'pending', 'software-possession', $6, $7, $8, now())
            on conflict (identity_id, device_public_id) do update
               set platform = excluded.platform,
                   display_name = coalesce(excluded.display_name, authlink.trusted_device.display_name),
                   key_alg = excluded.key_alg,
                   public_key_jwk = excluded.public_key_jwk,
                   last_seen_at = now(),
                   version = authlink.trusted_device.version + 1
             where authlink.trusted_device.revoked_at is null
            returning id, device_public_id, platform, display_name, trust_state, key_alg, public_key_jwk
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(identity_id)
        .bind(device_public_id)
        .bind(platform)
        .bind(display_name)
        .bind(key_alg)
        .bind(public_key_jwk)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(device_record_from_row))
    }

    pub async fn load_trusted_device(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        device_id: Uuid,
    ) -> Result<Option<TrustedDeviceRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            select id, device_public_id, platform, display_name, trust_state, key_alg, public_key_jwk
              from authlink.trusted_device
             where id = $1 and tenant_id = $2 and identity_id = $3
               and trust_state = 'trusted' and revoked_at is null
            "#,
        )
        .bind(device_id)
        .bind(tenant_id)
        .bind(identity_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(device_record_from_row))
    }

    pub async fn mark_device_trusted(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        device_id: Uuid,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            update authlink.trusted_device
               set trust_state = 'trusted', proofed_at = now(), last_seen_at = now(),
                   version = version + 1
             where id = $1 and tenant_id = $2 and identity_id = $3 and revoked_at is null
            "#,
        )
        .bind(device_id)
        .bind(tenant_id)
        .bind(identity_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn bind_session_to_trusted_device(
        &self,
        session_id: Uuid,
        tenant_id: Uuid,
        identity_id: Uuid,
        device_id: Uuid,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            update authlink.session s
               set trusted_device_id = $4,
                   auth_strength = 'oidc+device-possession',
                   assurance_evidence = coalesce(s.assurance_evidence, '{}'::jsonb)
                     || jsonb_build_object(
                          'device_possession',
                          jsonb_build_object('device_id', $4::text, 'verified_at', now())
                        )
              from authlink.trusted_device d
             where s.id = $1 and s.tenant_id = $2 and s.identity_id = $3
               and s.state = 'active' and s.revoked_at is null and s.expires_at > now()
               and d.id = $4 and d.tenant_id = $2 and d.identity_id = $3
               and d.trust_state = 'trusted' and d.revoked_at is null
            "#,
        )
        .bind(session_id)
        .bind(tenant_id)
        .bind(identity_id)
        .bind(device_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn list_trusted_devices(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<TrustedDeviceMetadata>, StoreError> {
        let rows = sqlx::query(
            r#"
            select id, device_public_id, platform, display_name, trust_state, key_alg, last_seen_at
              from authlink.trusted_device
             where tenant_id = $1 and identity_id = $2 and revoked_at is null
             order by last_seen_at desc nulls last, created_at desc
            "#,
        )
        .bind(tenant_id)
        .bind(identity_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| TrustedDeviceMetadata {
                id: row.get("id"),
                device_public_id: row.get("device_public_id"),
                platform: row.get("platform"),
                display_name: row.get("display_name"),
                trust_state: row.get("trust_state"),
                key_alg: row.get("key_alg"),
                last_seen_at: row.get("last_seen_at"),
            })
            .collect())
    }

    pub async fn revoke_trusted_device(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        device_id: Uuid,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            r#"
            update authlink.trusted_device
               set trust_state = 'revoked', revoked_at = now(), version = version + 1
             where id = $1 and tenant_id = $2 and identity_id = $3 and revoked_at is null
            "#,
        )
        .bind(device_id)
        .bind(tenant_id)
        .bind(identity_id)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 1 {
            sqlx::query(
                r#"
                update authlink.session
                   set state = 'revoked', revoked_at = now()
                 where tenant_id = $1 and identity_id = $2 and trusted_device_id = $3
                   and state = 'active'
                "#,
            )
            .bind(tenant_id)
            .bind(identity_id)
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn create_vault_item(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        identity_id: Uuid,
        kind: &str,
        purpose: &str,
        envelope: &EncryptedEnvelope,
    ) -> Result<(), StoreError> {
        let key_version = i32::try_from(envelope.key_version).map_err(|_| StoreError::InvalidInteger("key_version"))?;
        sqlx::query(
            r#"
            insert into authlink.vault_item
              (id, tenant_id, identity_id, kind, purpose, key_version, envelope)
            values ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(identity_id)
        .bind(kind)
        .bind(purpose)
        .bind(key_version)
        .bind(serde_json::to_value(envelope)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn load_vault_item(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        id: Uuid,
    ) -> Result<Option<VaultItemRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            select id, tenant_id, identity_id, kind, purpose, key_version, envelope
              from authlink.vault_item
             where id = $1 and tenant_id = $2 and identity_id = $3 and state = 'active'
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(identity_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|row| {
            let key_version: i32 = row.try_get("key_version")?;
            let envelope_value: serde_json::Value = row.try_get("envelope")?;
            Ok(VaultItemRecord {
                id: row.try_get("id")?,
                tenant_id: row.try_get("tenant_id")?,
                identity_id: row.try_get("identity_id")?,
                kind: row.try_get("kind")?,
                purpose: row.try_get("purpose")?,
                key_version: u32::try_from(key_version).map_err(|_| StoreError::InvalidInteger("key_version"))?,
                envelope: serde_json::from_value(envelope_value)?,
            })
        }).transpose()
    }

    pub async fn list_vault_items(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> Result<Vec<VaultItemMetadata>, StoreError> {
        let rows = sqlx::query(
            r#"
            select id, kind, purpose, key_version
              from authlink.vault_item
             where tenant_id = $1 and identity_id = $2 and state = 'active'
             order by created_at desc
            "#,
        )
        .bind(tenant_id)
        .bind(identity_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|row| {
            let key_version: i32 = row.try_get("key_version")?;
            Ok(VaultItemMetadata {
                id: row.try_get("id")?,
                kind: row.try_get("kind")?,
                purpose: row.try_get("purpose")?,
                key_version: u32::try_from(key_version).map_err(|_| StoreError::InvalidInteger("key_version"))?,
            })
        }).collect()
    }

    pub async fn update_vault_envelope(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        id: Uuid,
        expected_key_version: u32,
        envelope: &EncryptedEnvelope,
    ) -> Result<bool, StoreError> {
        let expected = i32::try_from(expected_key_version).map_err(|_| StoreError::InvalidInteger("expected_key_version"))?;
        let next = i32::try_from(envelope.key_version).map_err(|_| StoreError::InvalidInteger("key_version"))?;
        let result = sqlx::query(
            r#"
            update authlink.vault_item
               set envelope = $5,
                   key_version = $6,
                   version = version + 1,
                   updated_at = now()
             where id = $1 and tenant_id = $2 and identity_id = $3
               and state = 'active' and key_version = $4
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(identity_id)
        .bind(expected)
        .bind(serde_json::to_value(envelope)?)
        .bind(next)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn delete_vault_item(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        id: Uuid,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            r#"
            update authlink.vault_item
               set state = 'deleted', deleted_at = now(), updated_at = now(), version = version + 1
             where id = $1 and tenant_id = $2 and identity_id = $3 and state = 'active'
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(identity_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn record_guardian_decision(
        &self,
        decision: &GuardianDecision,
        signals: &GuardianSignals,
        correlation_id: Uuid,
    ) -> Result<Uuid, StoreError> {
        let id = Uuid::now_v7();
        let level = serde_json::to_value(&decision.level)?.as_str().unwrap_or("unknown").to_owned();
        sqlx::query(
            r#"
            insert into authlink.guardian_decision
              (id, score, level, action, reasons, signal_summary, correlation_id)
            values ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(id)
        .bind(i16::from(decision.score))
        .bind(level)
        .bind(&decision.action)
        .bind(serde_json::to_value(&decision.reasons)?)
        .bind(serde_json::to_value(signals)?)
        .bind(correlation_id)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }
}

fn device_record_from_row(row: sqlx::postgres::PgRow) -> TrustedDeviceRecord {
    TrustedDeviceRecord {
        id: row.get("id"),
        device_public_id: row.get("device_public_id"),
        platform: row.get("platform"),
        display_name: row.get("display_name"),
        trust_state: row.get("trust_state"),
        key_alg: row.get("key_alg"),
        public_key_jwk: row.get("public_key_jwk"),
    }
}
