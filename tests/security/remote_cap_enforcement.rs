//! Security tests for bd-1nfu RemoteCap enforcement.
//!
//! Verifies:
//! - network-bound operations fail without RemoteCap
//! - signature/expiry/scope/replay/revocation checks are fail-closed
//! - local-only operations remain functional without RemoteCap
//! - network guard enforces centralized capability gate

use ed25519_dalek::{Signer, SigningKey};
use frankenengine_node::security::impossible_default::{
    CapabilityEnforcer, CapabilityToken, ERR_IBD_SUBJECT_MISMATCH, ImpossibleCapability,
};
use frankenengine_node::security::network_guard::{
    Action, EgressPolicy, EgressRule, NetworkGuard, Protocol,
};
use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, ConnectivityMode, RemoteOperation, RemoteScope,
};

fn provider() -> CapabilityProvider {
    CapabilityProvider::new("remote-cap-test-secret")
        .expect("remote cap test signing secret should be valid")
}

#[test]
fn capability_provider_debug_redacts_signing_secret() {
    let secret = "debug-provider-secret-do-not-leak";
    let provider = CapabilityProvider::new(secret).expect("provider secret should be valid");

    let rendered = format!("{provider:?}");

    assert!(rendered.contains("CapabilityProvider"));
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains(secret));
}

#[test]
fn capability_gate_debug_redacts_verification_secret() {
    let secret = "debug-gate-secret-do-not-leak";
    let gate = CapabilityGate::new(secret).expect("gate secret should be valid");

    let rendered = format!("{gate:?}");

    assert!(rendered.contains("CapabilityGate"));
    assert!(rendered.contains("<redacted>"));
    assert!(rendered.contains("Connected"));
    assert!(!rendered.contains(secret));
}

fn full_scope() -> RemoteScope {
    RemoteScope::new(
        vec![
            RemoteOperation::NetworkEgress,
            RemoteOperation::FederationSync,
            RemoteOperation::RevocationFetch,
            RemoteOperation::RemoteAttestationVerify,
            RemoteOperation::TelemetryExport,
        ],
        vec![
            "http://api.example.com".to_string(),
            "http://egress.example.com".to_string(),
            "https://egress.example.com".to_string(),
            "https://api.example.com".to_string(),
            "https://attestation.example.com".to_string(),
            "https://telemetry.example.com".to_string(),
            "revocation://global-feed".to_string(),
            "federation://cluster-a".to_string(),
        ],
    )
}

fn issue_cap(single_use: bool) -> frankenengine_node::security::remote_cap::RemoteCap {
    provider()
        .issue(
            "ops-control-plane",
            full_scope(),
            1_700_000_000,
            3_600,
            true,
            single_use,
            "trace-issue",
        )
        .expect("issue")
        .0
}

fn sign_impossible_default_token(token: &mut CapabilityToken, signing_key: &SigningKey) {
    let hash = token.content_hash();
    let signature = signing_key.sign(hash.as_bytes());
    token.signature = hex::encode(signature.to_bytes());
}

fn impossible_default_token_for(
    subject: &str,
    capability: ImpossibleCapability,
    signing_key: &SigningKey,
) -> CapabilityToken {
    let mut token = CapabilityToken {
        token_id: format!("subject-bound-{}", capability.label()),
        capability,
        issuer: "security-test-issuer".to_string(),
        subject: subject.to_string(),
        issued_at_ms: 1_700_000_000_000,
        expires_at_ms: 1_700_000_060_000,
        signature: String::new(),
        justification: "subject-bound capability regression".to_string(),
    };
    sign_impossible_default_token(&mut token, signing_key);
    token
}

#[test]
fn all_network_operations_require_token() {
    let mut gate =
        CapabilityGate::new("remote-cap-test-secret").expect("remote cap test gate should be valid");

    let ops = [
        (RemoteOperation::NetworkEgress, "https://egress.example.com"),
        (RemoteOperation::FederationSync, "federation://cluster-a"),
        (
            RemoteOperation::RevocationFetch,
            "revocation://global-feed/latest",
        ),
        (
            RemoteOperation::RemoteAttestationVerify,
            "https://attestation.example.com/verify",
        ),
        (
            RemoteOperation::TelemetryExport,
            "https://telemetry.example.com/push",
        ),
    ];

    for (idx, (operation, endpoint)) in ops.iter().enumerate() {
        let err = gate
            .authorize_network(
                None,
                *operation,
                endpoint,
                1_700_000_100 + idx as u64,
                "trace-missing",
            )
            .expect_err("missing token should fail");
        assert_eq!(err.code(), "REMOTECAP_MISSING");
        assert_eq!(err.compatibility_code(), Some("ERR_REMOTE_CAP_REQUIRED"));
    }
}

#[test]
fn remote_cap_signed_subject_mismatch_is_rejected() {
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let capability = ImpossibleCapability::OutboundNetwork;
    let token = impossible_default_token_for("subject-a", capability, &signing_key);
    let mut enforcer = CapabilityEnforcer::with_ed25519_verifier(signing_key.verifying_key());

    let mismatch_err = enforcer
        .opt_in(token.clone(), "subject-b", 1_700_000_001_000)
        .expect_err("token signed for subject A must not opt in subject B");
    assert_eq!(mismatch_err.code, ERR_IBD_SUBJECT_MISMATCH);
    assert!(!enforcer.is_enabled(capability));
    assert_eq!(
        enforcer
            .audit_log()
            .last()
            .map(|entry| entry.event_code.as_str()),
        Some(ERR_IBD_SUBJECT_MISMATCH)
    );

    enforcer
        .opt_in(token, "subject-a", 1_700_000_001_000)
        .expect("signed subject may opt in itself");
    enforcer
        .enforce(capability, "subject-a", 1_700_000_002_000)
        .expect("signed subject may use its capability");

    let cross_actor_err = enforcer
        .enforce(capability, "subject-b", 1_700_000_003_000)
        .expect_err("enabled capability must not become global");
    assert_eq!(cross_actor_err.code, ERR_IBD_SUBJECT_MISMATCH);
}

#[test]
fn valid_token_allows_scoped_operations() {
    let cap = issue_cap(false);
    let mut gate =
        CapabilityGate::new("remote-cap-test-secret").expect("remote cap test gate should be valid");
    gate.authorize_network(
        Some(&cap),
        RemoteOperation::FederationSync,
        "federation://cluster-a",
        1_700_000_010,
        "trace-ok",
    )
    .expect("scoped operation should pass");
}

#[test]
fn forged_signature_is_rejected() {
    let cap = issue_cap(false);
    let mut tampered = serde_json::to_value(&cap).expect("to value");
    tampered["signature"] = serde_json::Value::String("forged-signature".to_string());
    let forged: frankenengine_node::security::remote_cap::RemoteCap =
        serde_json::from_value(tampered).expect("from value");

    let mut gate =
        CapabilityGate::new("remote-cap-test-secret").expect("remote cap test gate should be valid");
    let err = gate
        .authorize_network(
            Some(&forged),
            RemoteOperation::TelemetryExport,
            "https://telemetry.example.com/push",
            1_700_000_020,
            "trace-forge",
        )
        .expect_err("forged token must fail");
    assert_eq!(err.code(), "REMOTECAP_INVALID");
}

#[test]
fn expired_token_is_rejected() {
    let cap = provider()
        .issue(
            "ops-control-plane",
            full_scope(),
            1_700_000_000,
            5,
            true,
            false,
            "trace-expired-issue",
        )
        .expect("issue")
        .0;
    let mut gate =
        CapabilityGate::new("remote-cap-test-secret").expect("remote cap test gate should be valid");
    let err = gate
        .authorize_network(
            Some(&cap),
            RemoteOperation::RevocationFetch,
            "revocation://global-feed/latest",
            1_700_000_100,
            "trace-expired-use",
        )
        .expect_err("expired token must fail");
    assert_eq!(err.code(), "REMOTECAP_EXPIRED");
}

#[test]
fn scope_escalation_is_rejected() {
    let narrow_scope = RemoteScope::new(
        vec![RemoteOperation::TelemetryExport],
        vec!["https://telemetry.example.com".to_string()],
    );
    let cap = provider()
        .issue(
            "ops-control-plane",
            narrow_scope,
            1_700_000_000,
            3_600,
            true,
            false,
            "trace-narrow-issue",
        )
        .expect("issue")
        .0;

    let mut gate =
        CapabilityGate::new("remote-cap-test-secret").expect("remote cap test gate should be valid");
    let err = gate
        .authorize_network(
            Some(&cap),
            RemoteOperation::FederationSync,
            "federation://cluster-a",
            1_700_000_010,
            "trace-scope-denied",
        )
        .expect_err("out-of-scope operation must fail");
    assert_eq!(err.code(), "REMOTECAP_SCOPE_DENIED");
}

#[test]
fn replay_of_consumed_single_use_token_is_rejected() {
    let cap = issue_cap(true);
    let mut gate =
        CapabilityGate::new("remote-cap-test-secret").expect("remote cap test gate should be valid");
    gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://telemetry.example.com/push",
        1_700_000_010,
        "trace-replay-first",
    )
    .expect("first use should pass");

    let err = gate
        .authorize_network(
            Some(&cap),
            RemoteOperation::TelemetryExport,
            "https://telemetry.example.com/push",
            1_700_000_011,
            "trace-replay-second",
        )
        .expect_err("replay must fail");
    assert_eq!(err.code(), "REMOTECAP_REPLAY");
}

#[test]
fn revocation_blocks_previously_valid_token() {
    let cap = issue_cap(false);
    let mut gate =
        CapabilityGate::new("remote-cap-test-secret").expect("remote cap test gate should be valid");
    gate.revoke(&cap, 1_700_000_020, "trace-revoke");

    let err = gate
        .authorize_network(
            Some(&cap),
            RemoteOperation::RevocationFetch,
            "revocation://global-feed/latest",
            1_700_000_021,
            "trace-after-revoke",
        )
        .expect_err("revoked token must fail");
    assert_eq!(err.code(), "REMOTECAP_REVOKED");
}

#[test]
fn local_only_mode_keeps_local_ops_functional() {
    let mut gate =
        CapabilityGate::with_mode("remote-cap-test-secret", ConnectivityMode::LocalOnly)
            .expect("remote cap test gate should be valid");
    gate.authorize_local_operation("evidence_ledger_append", 1_700_000_030, "trace-local-op");
    let event = gate.audit_log().last().expect("local event");
    assert_eq!(event.event_code, "REMOTECAP_LOCAL_MODE_ACTIVE");
    assert!(event.allowed);
}

#[test]
fn network_guard_is_enforced_by_capability_gate() {
    let mut policy = EgressPolicy::new("conn-remote-cap".to_string(), Action::Deny);
    policy
        .add_rule(EgressRule {
            host: "api.example.com".to_string(),
            port: Some(443),
            action: Action::Allow,
            protocol: Protocol::Http,
        })
        .expect("add rule");
    let mut guard = NetworkGuard::new(policy);
    let mut gate =
        CapabilityGate::new("remote-cap-test-secret").expect("remote cap test gate should be valid");

    let err = guard
        .process_egress(
            "api.example.com",
            443,
            Protocol::Http,
            None,
            &mut gate,
            "trace-guard-missing",
            "ts",
            1_700_000_040,
        )
        .expect_err("missing cap must fail before policy allow");

    match err {
        frankenengine_node::security::network_guard::GuardError::RemoteCapDenied {
            code, ..
        } => {
            assert_eq!(code, "REMOTECAP_MISSING");
        }
        other => panic!("expected GuardError::RemoteCapDenied, got {other:?}"),
    }

    let cap = issue_cap(false);
    let ok = guard.process_egress(
        "api.example.com",
        443,
        Protocol::Http,
        Some(&cap),
        &mut gate,
        "trace-guard-ok",
        "ts",
        1_700_000_041,
    );
    assert!(ok.is_ok(), "valid cap should permit policy evaluation");
}
