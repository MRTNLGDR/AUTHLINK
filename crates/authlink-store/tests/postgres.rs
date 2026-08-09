use authlink_contracts::{GuardianDecision, GuardianSignals, RiskLevel};
use authlink_store::AuthlinkStore;
use authlink_vault::{KeyRing, MasterKey, VaultBinding};
use serde_json::json;
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
    assert_eq!(session.trusted_device_id, None);

    assert!(store.revoke_session(session_id).await.expect("revoke session"));
    assert!(store.load_active_session(session_id).await.expect("reload revoked session").is_none());
}

#[tokio::test]
async fn device_challenges_are_single_use_and_revocation_kills_bound_sessions() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL required for integration test");
    let store = AuthlinkStore::connect(&database_url).await.expect("connect PostgreSQL");
    let tenant_id = Uuid::now_v7();
    let subject = format!("device-test:{}", Uuid::now_v7());
    let identity_id = store
        .upsert_oidc_identity(tenant_id, &subject, Some("Device Test User"))
        .await
        .expect("create identity");
    let session_id = Uuid::new_v4();
    store
        .create_session(session_id, tenant_id, identity_id, "authlink-web", "suite.access", "oidc", 3600)
        .await
        .expect("create session");

    let challenge_id = Uuid::now_v7();
    let nonce = [3_u8; 32];
    store
        .create_device_challenge(
            challenge_id,
            tenant_id,
            identity_id,
            session_id,
            None,
            "enroll",
            &nonce,
            120,
        )
        .await
        .expect("create challenge");

    let consumed = store
        .consume_device_challenge(challenge_id, tenant_id, identity_id, session_id, "enroll")
        .await
        .expect("consume challenge")
        .expect("challenge should be valid once");
    assert_eq!(consumed.nonce, nonce);
    assert!(store
        .consume_device_challenge(challenge_id, tenant_id, identity_id, session_id, "enroll")
        .await
        .expect("replay query")
        .is_none());

    let device_id = Uuid::now_v7();
    let public_id = format!("p256-fixture-{}", Uuid::now_v7());
    let public_key = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "y": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    });
    let pending = store
        .upsert_unrevoked_device(
            device_id,
            tenant_id,
            identity_id,
            &public_id,
            "webcrypto:p256",
            Some("Browser test"),
            "ECDSA-P256-SHA256",
            &public_key,
        )
        .await
        .expect("create pending device")
        .expect("device must not be revoked");
    assert_eq!(pending.trust_state, "pending");
    assert!(store
        .mark_device_trusted(tenant_id, identity_id, pending.id)
        .await
        .expect("mark trusted"));
    assert!(store
        .bind_session_to_trusted_device(session_id, tenant_id, identity_id, pending.id)
        .await
        .expect("bind trusted device"));

    let session = store
        .load_active_session(session_id)
        .await
        .expect("load bound session")
        .expect("session still active");
    assert_eq!(session.trusted_device_id, Some(pending.id));
    assert_eq!(session.auth_strength, "oidc+device-possession");
    assert!(session.assurance_evidence.get("device_possession").is_some());

    let devices = store
        .list_trusted_devices(tenant_id, identity_id)
        .await
        .expect("list devices");
    assert!(devices.iter().any(|device| device.id == pending.id && device.trust_state == "trusted"));

    assert!(store
        .revoke_trusted_device(tenant_id, identity_id, pending.id)
        .await
        .expect("revoke device"));
    assert!(store
        .load_active_session(session_id)
        .await
        .expect("session lookup after device revoke")
        .is_none());

    let resurrect = store
        .upsert_unrevoked_device(
            Uuid::now_v7(),
            tenant_id,
            identity_id,
            &public_id,
            "webcrypto:p256",
            Some("Browser test"),
            "ECDSA-P256-SHA256",
            &public_key,
        )
        .await
        .expect("revoked key upsert must be handled");
    assert!(resurrect.is_none(), "revoked key fingerprint must not silently become trusted again");
}

#[tokio::test]
async fn vault_persists_ciphertext_only_and_rotates_wrapped_key() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL required for integration test");
    let store = AuthlinkStore::connect(&database_url).await.expect("connect PostgreSQL");
    let tenant_id = Uuid::now_v7();
    let subject = format!("vault-test:{}", Uuid::now_v7());
    let identity_id = store
        .upsert_oidc_identity(tenant_id, &subject, Some("Vault Test User"))
        .await
        .expect("create identity");
    let item_id = Uuid::now_v7();
    let purpose = "credential.store";
    let binding = VaultBinding::new(tenant_id, identity_id, item_id, purpose);
    let old_key = MasterKey::new([7; 32], 1);
    let old_ring = KeyRing::new(1, [old_key]).expect("old key ring");
    let plaintext = br#"{"username":"alice","password":"super-secret-password"}"#;
    let envelope = old_ring.encrypt(&binding, plaintext).expect("encrypt vault payload");

    store
        .create_vault_item(item_id, tenant_id, identity_id, "credential", purpose, &envelope)
        .await
        .expect("persist encrypted envelope");

    let raw_envelope: String = sqlx::query_scalar("select envelope::text from authlink.vault_item where id = $1")
        .bind(item_id)
        .fetch_one(store.pool())
        .await
        .expect("read raw persisted envelope");
    assert!(!raw_envelope.contains("super-secret-password"));
    assert!(!raw_envelope.contains("alice"));

    let loaded = store
        .load_vault_item(tenant_id, identity_id, item_id)
        .await
        .expect("load vault item")
        .expect("vault item exists");
    assert_eq!(old_ring.decrypt(&binding, &loaded.envelope).expect("decrypt").as_slice(), plaintext);

    let wrong_identity = Uuid::now_v7();
    assert!(store
        .load_vault_item(tenant_id, wrong_identity, item_id)
        .await
        .expect("owner-scoped lookup")
        .is_none());

    let rotation_ring = KeyRing::new(2, [MasterKey::new([7; 32], 1), MasterKey::new([9; 32], 2)])
        .expect("rotation ring");
    let rotated = rotation_ring.rewrap_to_active(&binding, &loaded.envelope).expect("rewrap DEK");
    assert_eq!(rotated.ciphertext_b64, loaded.envelope.ciphertext_b64);
    assert!(store
        .update_vault_envelope(tenant_id, identity_id, item_id, 1, &rotated)
        .await
        .expect("persist rewrap"));

    let after_rotation = store
        .load_vault_item(tenant_id, identity_id, item_id)
        .await
        .expect("reload rotated item")
        .expect("rotated item exists");
    assert_eq!(after_rotation.key_version, 2);
    assert_eq!(rotation_ring.decrypt(&binding, &after_rotation.envelope).expect("decrypt rotated").as_slice(), plaintext);

    assert!(store.delete_vault_item(tenant_id, identity_id, item_id).await.expect("soft delete vault item"));
    assert!(store.load_vault_item(tenant_id, identity_id, item_id).await.expect("reload deleted item").is_none());
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
