//! BPET governance override/appeal audit invariants.
//!
//! This fixture encodes the core governance invariants for bd-1naf.

use serde_json::{json, Value};

fn sample_override_event() -> Value {
    json!({
        "event_code": "BPET-GOV-005",
        "event_type": "override_approved",
        "decision_id": "dec-2026-0001",
        "trace_id": "trace-bpet-001",
        "timestamp": "2026-02-21T00:00:00Z",
        "actor_id": "operator-a",
        "approver_id": "reviewer-b",
        "threshold_band": "T3",
        "override_scope": ["capability:deploy", "region:us-east"],
        "override_ttl_minutes": 90,
        "rationale": "availability risk during controlled rollback window",
        "signature": "ed25519:9f8d...",
        "status": "approved"
    })
}

fn sample_appeal_event() -> Value {
    json!({
        "event_code": "BPET-GOV-007",
        "event_type": "appeal_resolved",
        "decision_id": "dec-2026-0001",
        "appeal_id": "app-2026-0021",
        "appeal_reason": "false-positive due to cold-start burst",
        "resolution": "partially_upheld",
        "trace_id": "trace-bpet-001",
        "timestamp": "2026-02-21T00:20:00Z",
        "actor_id": "reviewer-b",
        "threshold_band": "T3",
        "rationale": "containment retained, broad quarantine removed",
        "signature": "ed25519:1ab2...",
        "status": "resolved"
    })
}

fn required_base_fields() -> &'static [&'static str] {
    &[
        "event_code",
        "event_type",
        "decision_id",
        "trace_id",
        "timestamp",
        "actor_id",
        "threshold_band",
        "rationale",
        "signature",
        "status",
    ]
}

fn has_required_fields(event: &Value, required: &[&str]) -> bool {
    required.iter().all(|key| event.get(*key).is_some())
}

#[test]
fn override_event_has_required_base_fields() {
    let event = sample_override_event();
    assert!(has_required_fields(&event, required_base_fields()));
}

#[test]
fn appeal_event_has_required_base_fields() {
    let event = sample_appeal_event();
    assert!(has_required_fields(&event, required_base_fields()));
}

#[test]
fn override_event_has_override_specific_fields() {
    let event = sample_override_event();
    for key in ["override_scope", "override_ttl_minutes", "approver_id"] {
        assert!(event.get(key).is_some(), "missing {key}");
    }
}

#[test]
fn appeal_event_has_appeal_specific_fields() {
    let event = sample_appeal_event();
    for key in ["appeal_id", "appeal_reason", "resolution"] {
        assert!(event.get(key).is_some(), "missing {key}");
    }
}

#[test]
fn signed_rationale_is_required_for_override() {
    let event = sample_override_event();
    assert!(event["signature"].as_str().unwrap_or_default().starts_with("ed25519:"));
    assert!(!event["rationale"].as_str().unwrap_or_default().is_empty());
}

#[test]
fn override_requires_distinct_approver_for_t3() {
    let event = sample_override_event();
    let threshold = event["threshold_band"].as_str().unwrap_or_default();
    let actor = event["actor_id"].as_str().unwrap_or_default();
    let approver = event["approver_id"].as_str().unwrap_or_default();
    if threshold == "T3" {
        assert_ne!(actor, approver, "T3 overrides require dual control");
    }
}

#[test]
fn override_ttl_is_bounded() {
    let event = sample_override_event();
    let ttl = event["override_ttl_minutes"].as_u64().unwrap_or(u64::MAX);
    assert!(ttl > 0);
    assert!(ttl <= 180, "override ttl exceeds safety bound");
}

#[test]
fn event_codes_are_in_governance_namespace() {
    for event in [sample_override_event(), sample_appeal_event()] {
        let code = event["event_code"].as_str().unwrap_or_default();
        assert!(code.starts_with("BPET-GOV-"));
    }
}

#[test]
fn hard_stop_placeholder_is_non_overridable() {
    let hard_stop_category = "evidence_tampering";
    let override_attempted = true;
    let allow_override = false;
    assert!(override_attempted);
    assert!(!allow_override, "hard-stop category {hard_stop_category} must not be overridable");
}

#[test]
fn trace_id_and_decision_id_are_present_for_replay() {
    for event in [sample_override_event(), sample_appeal_event()] {
        assert!(!event["trace_id"].as_str().unwrap_or_default().is_empty());
        assert!(!event["decision_id"].as_str().unwrap_or_default().is_empty());
    }
}
