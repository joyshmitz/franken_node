//! Integration tests for bd-8uvb: Overlapping-lease conflict policy.

use frankenengine_node::connector::lease_conflict::*;

fn lease(id: &str, resource: &str, purpose: &str, granted: u64, ttl: u64, tier: &str) -> ActiveLease {
    ActiveLease {
        lease_id: id.into(),
        holder: format!("h-{id}"),
        resource: resource.into(),
        purpose: purpose.into(),
        granted_at: granted,
        expires_at: granted + ttl,
        tier: tier.into(),
    }
}

#[test]
fn inv_olc_deterministic() {
    let leases = vec![
        lease("l1", "r", "Operation", 100, 60, "Standard"),
        lease("l2", "r", "Operation", 110, 60, "Standard"),
    ];
    let policy = ConflictPolicy::default_policy();
    let (r1, _, _) = process_conflicts(&leases, "r", 120, &policy, "tr", "a", "ts");
    let (r2, _, _) = process_conflicts(&leases, "r", 120, &policy, "tr", "a", "ts");
    assert_eq!(r1.len(), r2.len());
    assert_eq!(r1[0].winner, r2[0].winner, "INV-OLC-DETERMINISTIC violated");
}

#[test]
fn inv_olc_dangerous_halt() {
    let leases = vec![
        lease("l1", "r", "Operation", 100, 60, "Dangerous"),
        lease("l2", "r", "StateWrite", 110, 60, "Standard"),
    ];
    let policy = ConflictPolicy::default_policy();
    let (resolutions, logs, errors) = process_conflicts(&leases, "r", 120, &policy, "tr", "a", "ts");
    assert_eq!(resolutions.len(), 0, "INV-OLC-DANGEROUS-HALT: should not resolve");
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].code(), "OLC_DANGEROUS_HALT");
    assert!(logs[0].halted, "INV-OLC-DANGEROUS-HALT: log must show halt");
}

#[test]
fn inv_olc_fork_log() {
    let leases = vec![
        lease("l1", "r", "Operation", 100, 60, "Standard"),
        lease("l2", "r", "StateWrite", 110, 60, "Standard"),
    ];
    let policy = ConflictPolicy::default_policy();
    let (_, logs, _) = process_conflicts(&leases, "r", 120, &policy, "trace-x", "action-y", "2026-01-01");
    assert_eq!(logs.len(), 1, "INV-OLC-FORK-LOG: must produce a log entry");
    assert_eq!(logs[0].trace_id, "trace-x");
    assert_eq!(logs[0].action_id, "action-y");
    assert!(!logs[0].entry_id.is_empty());
}

#[test]
fn inv_olc_classified() {
    let leases = vec![
        lease("l1", "r", "Operation", 100, 60, "Dangerous"),
        lease("l2", "r", "Operation", 110, 60, "Standard"),
    ];
    let policy = ConflictPolicy::default_policy();
    let (_, _, errors) = process_conflicts(&leases, "r", 120, &policy, "tr", "a", "ts");
    for e in &errors {
        assert!(!e.code().is_empty(), "INV-OLC-CLASSIFIED: error must have a code");
    }
}

#[test]
fn purpose_priority_migration_wins() {
    let leases = vec![
        lease("l1", "r", "Operation", 100, 60, "Risky"),
        lease("l2", "r", "MigrationHandoff", 110, 60, "Risky"),
    ];
    let mut policy = ConflictPolicy::default_policy();
    policy.halt_on_dangerous = false; // risky won't halt anyway
    let (resolutions, _, _) = process_conflicts(&leases, "r", 120, &policy, "tr", "a", "ts");
    assert_eq!(resolutions[0].winner, "l2");
}

#[test]
fn no_conflict_no_logs() {
    let leases = vec![
        lease("l1", "r", "Operation", 100, 50, "Standard"),
        lease("l2", "r", "Operation", 200, 50, "Standard"),
    ];
    let policy = ConflictPolicy::default_policy();
    let (resolutions, logs, errors) = process_conflicts(&leases, "r", 210, &policy, "tr", "a", "ts");
    assert!(resolutions.is_empty());
    assert!(logs.is_empty());
    assert!(errors.is_empty());
}
