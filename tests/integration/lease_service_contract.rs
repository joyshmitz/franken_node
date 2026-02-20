//! Integration tests for bd-bq6y: Generic lease service.
//!
//! Verifies deterministic expiry, renewal semantics, stale rejection,
//! and purpose enforcement.

use frankenengine_node::connector::lease_service::*;

#[test]
fn inv_ls_expiry_deterministic() {
    let mut svc = LeaseService::new();
    let l = svc.grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts");
    // At boundary: not expired
    assert!(!l.is_expired(160), "INV-LS-EXPIRY: should not expire at boundary");
    // Past boundary: expired
    assert!(l.is_expired(161), "INV-LS-EXPIRY: should expire past TTL");
}

#[test]
fn inv_ls_renewal_active_only() {
    let mut svc = LeaseService::new();
    let l = svc.grant("h", LeasePurpose::StateWrite, 60, 100, "tr", "ts");
    // Renew while active
    let renewed = svc.renew(&l.lease_id, 150, "tr2", "ts2").unwrap();
    assert!(renewed.is_active(200), "INV-LS-RENEWAL: renewed lease should be active");
    // Cannot renew expired
    let err = svc.renew(&l.lease_id, 300, "tr3", "ts3").unwrap_err();
    assert_eq!(err.code(), "LS_EXPIRED", "INV-LS-RENEWAL: expired renew should fail");
}

#[test]
fn inv_ls_stale_reject_expired() {
    let mut svc = LeaseService::new();
    let l = svc.grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts");
    let err = svc.use_lease(&l.lease_id, LeasePurpose::Operation, 200, "tr2", "ts2").unwrap_err();
    assert_eq!(err.code(), "LS_STALE_USE", "INV-LS-STALE-REJECT violated");
}

#[test]
fn inv_ls_stale_reject_revoked() {
    let mut svc = LeaseService::new();
    let l = svc.grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts");
    svc.revoke(&l.lease_id, "tr", "ts").unwrap();
    let err = svc.use_lease(&l.lease_id, LeasePurpose::Operation, 110, "tr2", "ts2").unwrap_err();
    assert_eq!(err.code(), "LS_STALE_USE", "INV-LS-STALE-REJECT violated for revoked");
}

#[test]
fn inv_ls_purpose_enforced() {
    let mut svc = LeaseService::new();
    let l = svc.grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts");
    let err = svc.use_lease(&l.lease_id, LeasePurpose::MigrationHandoff, 110, "tr2", "ts2").unwrap_err();
    assert_eq!(err.code(), "LS_PURPOSE_MISMATCH", "INV-LS-PURPOSE violated");
}

#[test]
fn all_three_purposes_supported() {
    let mut svc = LeaseService::new();
    let l1 = svc.grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts");
    let l2 = svc.grant("h", LeasePurpose::StateWrite, 60, 100, "tr", "ts");
    let l3 = svc.grant("h", LeasePurpose::MigrationHandoff, 60, 100, "tr", "ts");
    assert!(svc.use_lease(&l1.lease_id, LeasePurpose::Operation, 110, "tr", "ts").is_ok());
    assert!(svc.use_lease(&l2.lease_id, LeasePurpose::StateWrite, 110, "tr", "ts").is_ok());
    assert!(svc.use_lease(&l3.lease_id, LeasePurpose::MigrationHandoff, 110, "tr", "ts").is_ok());
}

#[test]
fn audit_trail_complete() {
    let mut svc = LeaseService::new();
    let l = svc.grant("h", LeasePurpose::Operation, 60, 100, "tr", "ts");
    svc.use_lease(&l.lease_id, LeasePurpose::Operation, 110, "tr2", "ts2").unwrap();
    svc.revoke(&l.lease_id, "tr3", "ts3").unwrap();
    assert_eq!(svc.decisions.len(), 3);
}
