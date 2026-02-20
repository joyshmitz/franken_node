//! Conformance tests for bd-y7lu: Revocation registry monotonicity.
//!
//! Verifies that revocation heads are strictly monotonic per zone,
//! stale updates are rejected, state is recoverable, and zones are isolated.

use frankenengine_node::supply_chain::revocation_registry::*;

fn head(zone: &str, seq: u64, artifact: &str) -> RevocationHead {
    RevocationHead {
        zone_id: zone.into(),
        sequence: seq,
        revoked_artifact: artifact.into(),
        reason: "test".into(),
        timestamp: "ts".into(),
        trace_id: "tr".into(),
    }
}

#[test]
fn inv_rev_monotonic_strictly_increasing() {
    let mut reg = RevocationRegistry::new();
    reg.init_zone("z1");
    reg.advance_head(head("z1", 1, "a1")).unwrap();
    reg.advance_head(head("z1", 2, "a2")).unwrap();
    reg.advance_head(head("z1", 10, "a3")).unwrap();
    assert_eq!(reg.current_head("z1").unwrap(), 10);
}

#[test]
fn inv_rev_stale_reject_lower() {
    let mut reg = RevocationRegistry::new();
    reg.init_zone("z1");
    reg.advance_head(head("z1", 5, "a1")).unwrap();
    let err = reg.advance_head(head("z1", 3, "a2")).unwrap_err();
    assert_eq!(err.code(), "REV_STALE_HEAD", "INV-REV-STALE-REJECT violated");
}

#[test]
fn inv_rev_stale_reject_equal() {
    let mut reg = RevocationRegistry::new();
    reg.init_zone("z1");
    reg.advance_head(head("z1", 5, "a1")).unwrap();
    let err = reg.advance_head(head("z1", 5, "a2")).unwrap_err();
    assert_eq!(err.code(), "REV_STALE_HEAD", "INV-REV-STALE-REJECT violated on equal seq");
}

#[test]
fn inv_rev_recoverable() {
    let log = vec![
        head("z1", 1, "a1"),
        head("z1", 2, "a2"),
        head("z2", 1, "a3"),
    ];
    let reg = RevocationRegistry::recover_from_log(&log).unwrap();
    assert_eq!(reg.current_head("z1").unwrap(), 2, "INV-REV-RECOVERABLE violated");
    assert_eq!(reg.current_head("z2").unwrap(), 1);
    assert!(reg.is_revoked("z1", "a1").unwrap());
    assert!(reg.is_revoked("z1", "a2").unwrap());
}

#[test]
fn inv_rev_zone_isolated() {
    let mut reg = RevocationRegistry::new();
    reg.init_zone("z1");
    reg.init_zone("z2");
    reg.advance_head(head("z1", 100, "a1")).unwrap();
    // z2 should still be at 0
    assert_eq!(reg.current_head("z2").unwrap(), 0, "INV-REV-ZONE-ISOLATED violated");
    // z2 can advance to 1 independently
    reg.advance_head(head("z2", 1, "a2")).unwrap();
    assert_eq!(reg.current_head("z2").unwrap(), 1);
}

#[test]
fn revoked_artifacts_tracked() {
    let mut reg = RevocationRegistry::new();
    reg.init_zone("z1");
    reg.advance_head(head("z1", 1, "art-compromised")).unwrap();
    assert!(reg.is_revoked("z1", "art-compromised").unwrap());
    assert!(!reg.is_revoked("z1", "art-safe").unwrap());
}

#[test]
fn recovery_fails_on_non_monotonic_log() {
    let log = vec![
        head("z1", 5, "a1"),
        head("z1", 3, "a2"),
    ];
    let err = RevocationRegistry::recover_from_log(&log).unwrap_err();
    assert_eq!(err.code(), "REV_RECOVERY_FAILED");
}

#[test]
fn audit_trail_complete() {
    let mut reg = RevocationRegistry::new();
    reg.init_zone("z1");
    reg.advance_head(head("z1", 1, "a1")).unwrap();
    let _ = reg.advance_head(head("z1", 1, "a2")); // stale
    assert_eq!(reg.audits.len(), 2);
    assert_eq!(reg.audits[0].action, "advanced");
    assert_eq!(reg.audits[1].action, "rejected_stale");
}
