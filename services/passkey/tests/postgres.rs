use authlink_passkey::{NewPasskeyCredential, PasskeyRepository};
use authlink_store::AuthlinkStore;
use uuid::Uuid;

#[tokio::test]
async fn passkey_state_is_owner_scoped_single_use_and_counter_safe() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL required for passkey integration test");
    let store = AuthlinkStore::connect(&database_url).await.expect("connect PostgreSQL");
    let repo = PasskeyRepository::new(store.clone());

    let tenant_id = Uuid::now_v7();
    let subject = format!("passkey-test:{}", Uuid::now_v7());
    let identity_id = store
        .upsert_oidc_identity(tenant_id, &subject, Some("Passkey Test User"))
        .await
        .expect("create identity");
    let session_id = Uuid::new_v4();
    store
        .create_session(session_id, tenant_id, identity_id, "authlink-web", "suite.access", "oidc", 3600)
        .await
        .expect("create session");

    let challenge_id = Uuid::now_v7();
    let challenge = [9_u8; 32];
    repo.create_challenge(
        challenge_id,
        tenant_id,
        identity_id,
        session_id,
        "authenticate",
        &challenge,
        120,
    )
    .await
    .expect("create passkey challenge");

    let consumed = repo
        .consume_challenge(challenge_id, tenant_id, identity_id, session_id, "authenticate")
        .await
        .expect("consume challenge")
        .expect("valid challenge once");
    assert_eq!(consumed.challenge, challenge);
    assert!(repo
        .consume_challenge(challenge_id, tenant_id, identity_id, session_id, "authenticate")
        .await
        .expect("replay query")
        .is_none());

    let credential_id = format!("cred-{}", Uuid::now_v7());
    let transports = vec!["internal".to_string(), "hybrid".to_string()];
    let record_id = Uuid::now_v7();
    repo.insert_credential(NewPasskeyCredential {
        id: record_id,
        tenant_id,
        identity_id,
        credential_id: &credential_id,
        public_key: &[0xa5, 0x01, 0x02, 0x03],
        counter: 4,
        transports: &transports,
        aaguid: Some("00000000-0000-0000-0000-000000000000"),
        attestation_format: Some("none"),
        credential_device_type: "multiDevice",
        credential_backed_up: true,
    })
    .await
    .expect("insert credential");

    let loaded = repo
        .load_credential(tenant_id, identity_id, &credential_id)
        .await
        .expect("load credential")
        .expect("credential exists");
    assert_eq!(loaded.counter, 4);
    assert_eq!(loaded.transports, transports);

    let wrong_owner = Uuid::now_v7();
    assert!(repo
        .load_credential(tenant_id, wrong_owner, &credential_id)
        .await
        .expect("wrong-owner lookup")
        .is_none());

    assert!(repo
        .update_counter(tenant_id, identity_id, &credential_id, 4, 5)
        .await
        .expect("advance counter"));
    assert!(!repo
        .update_counter(tenant_id, identity_id, &credential_id, 4, 6)
        .await
        .expect("stale counter update"));

    let before = store
        .load_active_session(session_id)
        .await
        .expect("load session before assertion")
        .expect("session active");
    assert_eq!(before.auth_strength, "oidc");

    assert!(repo
        .mark_session_passkey_verified(
            session_id,
            tenant_id,
            identity_id,
            &credential_id,
            "multiDevice",
            true,
        )
        .await
        .expect("write passkey assurance"));

    let after = store
        .load_active_session(session_id)
        .await
        .expect("load session after assertion")
        .expect("session active");
    assert_eq!(after.auth_strength, "passkey");
    assert_eq!(after.assurance_evidence["webauthn"]["credential_id"], credential_id);
    assert_eq!(after.assurance_evidence["webauthn"]["user_verified"], true);

    assert!(repo
        .revoke_credential(tenant_id, identity_id, &credential_id)
        .await
        .expect("revoke credential"));
    assert!(repo
        .load_credential(tenant_id, identity_id, &credential_id)
        .await
        .expect("load revoked credential")
        .is_none());
}
