use authlink_contracts::{GuardianDecision, GuardianSignals, RiskLevel};
use authlink_store::AuthlinkStore;
use uuid::Uuid;

#[tokio::test]
async fn ceremony_is_persisted_with_optimistic_concurrency() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL required for integration test");
    let store = AuthlinkStore::connect(&database_url).await.expect("connect PostgreSQL");
    let ceremony_id = Uuid::now_v7();

    let initial = store.ensure_ceremony(ceremony_id, 16).await.expect("create ceremony");
    assert_eq!(initial.completed_steps, 0);

    let updated = store
        .advance_ceremony(ceremony_id, 0, 1, "account", "anonymous", false, 24, false)
        .await
        .expect("advance ceremony");
    assert!(updated);

    let stale_write = store
        .advance_ceremony(ceremony_id, 0, 1, "account", "anonymous", false, 24, false)
        .await
        .expect("stale update should be handled without database error");
    assert!(!stale_write);

    let loaded = store.load_ceremony(ceremony_id).await.expect("reload ceremony");
    assert_eq!(loaded.completed_steps, 1);
}

#[tokio::test]
async fn oidc_identity_and_session_are_persisted_and_revocable() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL required for integration test");
    let store = AuthlinkStore::connect(&database_url).await.expect("connect PostgreSQL");
    let tenant_id = Uuid::now_v7();
    let subject = format!("oidc-test:{}", Uuid::now_v7());
    let identity_id = store
        .upsert_oidc_identity(tenant_id, &subject, Some("OIDC Test User"))
        .await
        .expect("upsert OIDC identity");
    let session_id = Uuid::new_v4();

    store
        .create_session(session_id, tenant_id, identity_id, "authlink-web", "suite.access", "oidc+pkce", 3600)
        .await
        .expect("create opaque AuthLink session");

    let session = store
        .load_active_session(session_id)
        .await
        .expect("load active session")
        .expect("session should be active");
    assert_eq!(session.subject, subject);
    assert_eq!(session.display_name.as_deref(), Some("OIDC Test User"));
    assert_eq!(session.auth_strength, "oidc+pkce");

    assert!(store.revoke_session(session_id).await.expect("revoke session"));
    assert!(store.load_active_session(session_id).await.expect("reload revoked session").is_none());
}

#[tokio::test]
async fn guardian_decision_is_append_only_recorded() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL required for integration test");
    let store = AuthlinkStore::connect(&database_url).await.expect("connect PostgreSQL");
    let correlation_id = Uuid::now_v7();
    let decision = GuardianDecision {
        score: 67,
        level: RiskLevel::High,
        action: "step-up".into(),
        reasons: vec!["integridade do dispositivo".into()],
        requires_step_up: true,
    };
    let signals = GuardianSignals {
        device_integrity_penalty: 57,
        ..GuardianSignals::default()
    };

    let id = store
        .record_guardian_decision(&decision, &signals, correlation_id)
        .await
        .expect("record Guardian decision");

    let count: i64 = sqlx::query_scalar("select count(*) from authlink.guardian_decision where id = $1 and correlation_id = $2")
        .bind(id)
        .bind(correlation_id)
        .fetch_one(store.pool())
        .await
        .expect("query persisted Guardian row");
    assert_eq!(count, 1);
}
