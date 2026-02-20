//! Conformance tests for bd-w0jq: Degraded-mode audit events.
//!
//! Verifies that every stale override emits a structured event,
//! schema is complete, events correlate to actions, and the log
//! is append-only.

use frankenengine_node::security::degraded_mode_audit::*;

fn event(action_id: &str, actor: &str, trace: &str) -> DegradedModeEvent {
    DegradedModeEvent {
        event_type: "degraded_mode_override".into(),
        action_id: action_id.into(),
        actor: actor.into(),
        tier: "Risky".into(),
        revocation_age_secs: 7200,
        max_age_secs: 3600,
        override_reason: "emergency".into(),
        trace_id: trace.into(),
        timestamp: "2026-01-01T00:00:00Z".into(),
    }
}

#[test]
fn inv_dm_event_required() {
    let mut log = DegradedModeAuditLog::new();
    log.emit(event("act-1", "admin", "tr-1")).unwrap();
    // The event MUST exist after emit
    assert!(log.assert_event_exists("act-1").is_ok(), "INV-DM-EVENT-REQUIRED violated");
}

#[test]
fn inv_dm_event_missing_is_failure() {
    let log = DegradedModeAuditLog::new();
    let err = log.assert_event_exists("act-missing").unwrap_err();
    assert_eq!(err.code(), "DM_EVENT_NOT_FOUND", "INV-DM-EVENT-REQUIRED: missing event must error");
}

#[test]
fn inv_dm_schema_complete_valid() {
    let e = event("act-1", "admin", "tr-1");
    assert!(validate_schema(&e).is_ok(), "INV-DM-SCHEMA-COMPLETE violated on valid event");
}

#[test]
fn inv_dm_schema_rejects_missing_actor() {
    let mut e = event("act-1", "admin", "tr-1");
    e.actor = String::new();
    let err = validate_schema(&e).unwrap_err();
    assert_eq!(err.code(), "DM_MISSING_FIELD", "INV-DM-SCHEMA-COMPLETE: must reject empty actor");
}

#[test]
fn inv_dm_schema_rejects_wrong_type() {
    let mut e = event("act-1", "admin", "tr-1");
    e.event_type = "wrong_type".into();
    let err = validate_schema(&e).unwrap_err();
    assert_eq!(err.code(), "DM_SCHEMA_VIOLATION");
}

#[test]
fn inv_dm_correlation_by_action() {
    let mut log = DegradedModeAuditLog::new();
    log.emit(event("act-1", "admin", "tr-1")).unwrap();
    log.emit(event("act-2", "ops", "tr-2")).unwrap();
    let found = log.find_by_action("act-1");
    assert_eq!(found.len(), 1, "INV-DM-CORRELATION violated");
    assert_eq!(found[0].action_id, "act-1");
}

#[test]
fn inv_dm_correlation_by_trace() {
    let mut log = DegradedModeAuditLog::new();
    log.emit(event("act-1", "admin", "tr-1")).unwrap();
    let found = log.find_by_trace("tr-1");
    assert_eq!(found.len(), 1, "INV-DM-CORRELATION violated for trace");
}

#[test]
fn inv_dm_immutable_count_only_grows() {
    let mut log = DegradedModeAuditLog::new();
    assert_eq!(log.count(), 0);
    log.emit(event("act-1", "admin", "tr-1")).unwrap();
    assert_eq!(log.count(), 1);
    log.emit(event("act-2", "ops", "tr-2")).unwrap();
    assert_eq!(log.count(), 2);
    // No API to remove or modify — INV-DM-IMMUTABLE by construction
}

#[test]
fn emit_rejects_invalid_and_preserves_log() {
    let mut log = DegradedModeAuditLog::new();
    log.emit(event("act-1", "admin", "tr-1")).unwrap();
    let mut bad = event("act-2", "", "tr-2");
    bad.actor = String::new();
    assert!(log.emit(bad).is_err());
    assert_eq!(log.count(), 1, "Invalid event must not be appended");
}
