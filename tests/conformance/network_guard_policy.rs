//! Network guard conformance tests (bd-2m2b).
//!
//! Verifies default-deny, rule ordering, audit emission, and
//! protocol separation.

use frankenengine_node::security::network_guard::*;

fn sample_policy() -> EgressPolicy {
    let mut policy = EgressPolicy::new("conn-1".into(), Action::Deny);
    policy.add_rule(EgressRule {
        host: "api.example.com".into(),
        port: Some(443),
        action: Action::Allow,
        protocol: Protocol::Http,
    });
    policy.add_rule(EgressRule {
        host: "*.trusted.com".into(),
        port: None,
        action: Action::Allow,
        protocol: Protocol::Http,
    });
    policy
}

#[test]
fn default_deny_applied() {
    let policy = EgressPolicy::new("conn-1".into(), Action::Deny);
    let (action, idx) = policy.evaluate("anything.com", 80, Protocol::Http);
    assert_eq!(action, Action::Deny);
    assert_eq!(idx, None);
}

#[test]
fn explicit_allow_overrides_default() {
    let policy = sample_policy();
    let (action, _) = policy.evaluate("api.example.com", 443, Protocol::Http);
    assert_eq!(action, Action::Allow);
}

#[test]
fn rules_evaluated_in_order() {
    let mut policy = EgressPolicy::new("conn-1".into(), Action::Deny);
    policy.add_rule(EgressRule {
        host: "*".into(), port: None, action: Action::Allow, protocol: Protocol::Http,
    });
    policy.add_rule(EgressRule {
        host: "evil.com".into(), port: None, action: Action::Deny, protocol: Protocol::Http,
    });
    let (action, idx) = policy.evaluate("evil.com", 80, Protocol::Http);
    assert_eq!(action, Action::Allow);
    assert_eq!(idx, Some(0));
}

#[test]
fn every_decision_emits_audit() {
    let mut guard = NetworkGuard::new(sample_policy());
    let _ = guard.process_egress("api.example.com", 443, Protocol::Http, "t1", "ts");
    let _ = guard.process_egress("unknown.com", 80, Protocol::Http, "t2", "ts");
    assert_eq!(guard.audit_log.len(), 2);
}

#[test]
fn audit_captures_trace_id() {
    let mut guard = NetworkGuard::new(sample_policy());
    let _ = guard.process_egress("api.example.com", 443, Protocol::Http, "trace-xyz", "ts");
    assert_eq!(guard.audit_log[0].trace_id, "trace-xyz");
}

#[test]
fn protocol_separation() {
    let policy = sample_policy(); // rules are HTTP only
    let (action, _) = policy.evaluate("api.example.com", 443, Protocol::Tcp);
    assert_eq!(action, Action::Deny); // TCP doesn't match HTTP rules
}

#[test]
fn wildcard_host_matching() {
    let policy = sample_policy();
    let (action, _) = policy.evaluate("sub.trusted.com", 443, Protocol::Http);
    assert_eq!(action, Action::Allow);
    let (action, _) = policy.evaluate("trusted.com", 443, Protocol::Http);
    assert_eq!(action, Action::Deny); // exact "trusted.com" doesn't match "*.trusted.com"
}
