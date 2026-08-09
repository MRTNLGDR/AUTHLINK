use authlink_contracts::{GuardianDecision, GuardianSignals};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::env;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub struct CeremonyRecord {
    pub id: Uuid,
    pub completed_steps: usize,
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
