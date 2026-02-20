//! Sandbox profile conformance tests (bd-3ua7).
//!
//! Verifies profile ordering, policy compilation determinism,
//! downgrade blocking, capability grants, and audit logging.

use frankenengine_node::security::sandbox_policy_compiler::*;

// === Profile ordering ===

#[test]
fn profiles_form_strict_total_order() {
    let levels: Vec<u8> = SandboxProfile::ALL.iter().map(|p| p.level()).collect();
    for i in 1..levels.len() {
        assert!(levels[i] > levels[i - 1], "profiles must be strictly ordered");
    }
}

// === Policy compilation determinism ===

#[test]
fn compilation_is_deterministic() {
    for p in &SandboxProfile::ALL {
        let a = compile_policy(*p);
        let b = compile_policy(*p);
        assert_eq!(a, b, "policy for {p} must be deterministic");
    }
}

#[test]
fn all_profiles_have_6_capabilities() {
    for p in &SandboxProfile::ALL {
        let policy = compile_policy(*p);
        assert_eq!(policy.grants.len(), 6);
    }
}

// === Downgrade blocking ===

#[test]
fn downgrade_blocked_without_override() {
    let mut t = ProfileTracker::new("conn-1".into(), SandboxProfile::Permissive);
    let err = t
        .change_profile(SandboxProfile::Strict, "test".into(), "t".into(), false)
        .unwrap_err();
    assert!(matches!(err, SandboxError::DowngradeBlocked { .. }));
}

#[test]
fn upgrade_always_allowed() {
    let mut t = ProfileTracker::new("conn-1".into(), SandboxProfile::Strict);
    t.change_profile(SandboxProfile::Moderate, "upgrade".into(), "t".into(), false).unwrap();
    t.change_profile(SandboxProfile::Permissive, "upgrade".into(), "t".into(), false).unwrap();
    assert_eq!(t.current_profile, SandboxProfile::Permissive);
}

// === Capability grants ===

#[test]
fn strict_denies_all() {
    let policy = compile_policy(SandboxProfile::Strict);
    for g in &policy.grants {
        assert_eq!(g.access, AccessLevel::Deny);
    }
}

#[test]
fn permissive_allows_all() {
    let policy = compile_policy(SandboxProfile::Permissive);
    for g in &policy.grants {
        assert_eq!(g.access, AccessLevel::Allow);
    }
}

// === Audit logging ===

#[test]
fn initial_assignment_audited() {
    let t = ProfileTracker::new("conn-1".into(), SandboxProfile::Strict);
    assert_eq!(t.audit_log.len(), 1);
    assert_eq!(t.audit_log[0].old_profile, None);
    assert_eq!(t.audit_log[0].new_profile, SandboxProfile::Strict);
}

#[test]
fn profile_change_audited() {
    let mut t = ProfileTracker::new("conn-1".into(), SandboxProfile::Strict);
    t.change_profile(SandboxProfile::Moderate, "needs net".into(), "t".into(), false).unwrap();
    assert_eq!(t.audit_log.len(), 2);
    let last = &t.audit_log[1];
    assert_eq!(last.old_profile, Some(SandboxProfile::Strict));
    assert_eq!(last.new_profile, SandboxProfile::Moderate);
}

// === Policy validation ===

#[test]
fn standard_policies_valid() {
    for p in &SandboxProfile::ALL {
        let policy = compile_policy(*p);
        assert!(validate_policy(&policy).is_ok());
    }
}
