use frankenengine_node::api::session_auth::{
    demo_session_lifecycle, demo_windowed_replay, event_codes, session_lifecycle_events,
    sign_handshake, MessageDirection, SessionConfig, SessionError, SessionLifecycleMessage,
    SessionLifecycleScenario, SessionManager,
};
use frankenengine_node::control_plane::control_epoch::ControlEpoch;
use frankenengine_node::control_plane::key_role_separation::{KeyRole, KeyRoleRegistry};
use frankenengine_node::security::epoch_scoped_keys::RootSecret;

fn lifecycle_scenario(max_sessions: usize) -> SessionLifecycleScenario {
    SessionLifecycleScenario {
        config: SessionConfig {
            replay_window: 0,
            max_sessions,
            session_timeout_ms: 60_000,
        },
        root_secret: RootSecret::from_bytes([0x42; 32]),
        epoch: ControlEpoch::from(7u64),
        session_id: "sess-real".to_string(),
        client_identity: "client-real".to_string(),
        server_identity: "server-real".to_string(),
        encryption_key_id: "enc-real".to_string(),
        signing_key_id: "sign-real".to_string(),
        established_at: 10_000,
        trace_id: "trace-real".to_string(),
        messages: vec![
            SessionLifecycleMessage {
                direction: MessageDirection::Send,
                sequence: 0,
                payload_hash: "payload-send-0".to_string(),
                timestamp: 10_100,
            },
            SessionLifecycleMessage {
                direction: MessageDirection::Receive,
                sequence: 0,
                payload_hash: "payload-recv-0".to_string(),
                timestamp: 10_200,
            },
        ],
        terminate_at: Some(10_300),
    }
}

fn bind_role_key(registry: &mut KeyRoleRegistry, key_id: &str, role: KeyRole) {
    let mut material = key_id.as_bytes().to_vec();
    material.extend_from_slice(&role.tag());
    registry
        .bind(
            key_id,
            role,
            material,
            "session-auth-test",
            9_999,
            60_000,
            "trace-real",
        )
        .expect("test key role binding should succeed");
}

fn role_checked_manager(registry: KeyRoleRegistry) -> (SessionManager, RootSecret, ControlEpoch) {
    let root_secret = RootSecret::from_bytes([0x42; 32]);
    let epoch = ControlEpoch::from(7u64);
    let manager = SessionManager::with_key_role_registry(
        SessionConfig {
            replay_window: 0,
            max_sessions: 4,
            session_timeout_ms: 60_000,
        },
        root_secret.clone(),
        epoch,
        registry,
    );
    (manager, root_secret, epoch)
}

#[test]
fn caller_supplied_lifecycle_emits_events() {
    let events = session_lifecycle_events(lifecycle_scenario(4))
        .expect("caller supplied lifecycle should execute");

    assert_eq!(events.len(), 4);
    assert_eq!(events[0].event_code, event_codes::SCC_SESSION_ESTABLISHED);
    assert_eq!(events[1].event_code, event_codes::SCC_MESSAGE_ACCEPTED);
    assert_eq!(events[2].event_code, event_codes::SCC_MESSAGE_ACCEPTED);
    assert_eq!(events[3].event_code, event_codes::SCC_SESSION_TERMINATED);
    assert!(events.iter().all(|event| event.session_id == "sess-real"));
}

#[test]
fn caller_supplied_lifecycle_propagates_typed_errors() {
    let err = session_lifecycle_events(lifecycle_scenario(0))
        .expect_err("max_sessions=0 must fail closed instead of producing demo events");

    assert!(matches!(err, SessionError::MaxSessionsReached { limit: 0 }));
}

#[test]
fn establishment_rejects_swapped_registered_key_roles() {
    let mut registry = KeyRoleRegistry::new();
    bind_role_key(&mut registry, "enc-real", KeyRole::Encryption);
    bind_role_key(&mut registry, "sign-real", KeyRole::Signing);
    let (mut manager, root_secret, epoch) = role_checked_manager(registry);

    let mac = sign_handshake(
        "sess-swap",
        "client-real",
        "server-real",
        "sign-real",
        "enc-real",
        epoch,
        10_000,
        &root_secret,
    );

    let err = manager
        .establish_session(
            "sess-swap".to_string(),
            "client-real".to_string(),
            "server-real".to_string(),
            "sign-real".to_string(),
            "enc-real".to_string(),
            10_000,
            "trace-real".to_string(),
            mac,
        )
        .expect_err("swapped key roles must fail closed");

    assert!(matches!(
        err,
        SessionError::RoleMismatch {
            expected_role,
            actual_role,
            ..
        } if expected_role == "Encryption" && actual_role == "Signing"
    ));
    assert!(manager.get_session("sess-swap").is_none());
}

#[test]
fn establishment_rejects_issuance_key_as_signing_key() {
    let mut registry = KeyRoleRegistry::new();
    bind_role_key(&mut registry, "enc-real", KeyRole::Encryption);
    bind_role_key(&mut registry, "issue-real", KeyRole::Issuance);
    let (mut manager, root_secret, epoch) = role_checked_manager(registry);

    let mac = sign_handshake(
        "sess-issue",
        "client-real",
        "server-real",
        "enc-real",
        "issue-real",
        epoch,
        10_000,
        &root_secret,
    );

    let err = manager
        .establish_session(
            "sess-issue".to_string(),
            "client-real".to_string(),
            "server-real".to_string(),
            "enc-real".to_string(),
            "issue-real".to_string(),
            10_000,
            "trace-real".to_string(),
            mac,
        )
        .expect_err("issuance key must not satisfy the signing role");

    assert!(matches!(
        err,
        SessionError::RoleMismatch {
            expected_role,
            actual_role,
            ..
        } if expected_role == "Signing" && actual_role == "Issuance"
    ));
    assert!(manager.get_session("sess-issue").is_none());
}

#[test]
fn deterministic_fixture_wrappers_remain_test_support_only() {
    let lifecycle_events = demo_session_lifecycle();
    assert_eq!(lifecycle_events.len(), 7);
    assert_eq!(
        lifecycle_events[0].event_code,
        event_codes::SCC_SESSION_ESTABLISHED
    );

    let replay_events = demo_windowed_replay();
    let rejected = replay_events
        .iter()
        .filter(|event| event.event_code == event_codes::SCC_MESSAGE_REJECTED)
        .count();
    assert_eq!(rejected, 1);
}
