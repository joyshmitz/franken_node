//! Integration tests for strict-plus isolation backend (bd-1vvs).

use frankenengine_node::security::isolation_backend::*;
use frankenengine_node::security::sandbox_policy_compiler::AccessLevel;

fn linux_kvm() -> PlatformCapabilities {
    PlatformCapabilities::from_values("linux", "x86_64", true, true, true, true, false, true)
}

fn linux_no_kvm() -> PlatformCapabilities {
    PlatformCapabilities::from_values("linux", "x86_64", false, true, true, true, false, false)
}

fn macos() -> PlatformCapabilities {
    PlatformCapabilities::from_values("macos", "aarch64", false, false, false, false, true, false)
}

#[test]
fn end_to_end_linux_kvm_selection() {
    let sel = select_backend(&linux_kvm()).unwrap();
    assert_eq!(sel.backend, IsolationBackend::MicroVm);
    assert_eq!(sel.equivalence, EquivalenceLevel::Full);
    assert!(verify_policy_enforcement(&sel).is_ok());
}

#[test]
fn end_to_end_linux_hardened_selection() {
    let sel = select_backend(&linux_no_kvm()).unwrap();
    assert_eq!(sel.backend, IsolationBackend::Hardened);
    assert!(verify_policy_enforcement(&sel).is_ok());
}

#[test]
fn end_to_end_macos_selection() {
    let sel = select_backend(&macos()).unwrap();
    assert_eq!(sel.backend, IsolationBackend::OsSandbox);
    assert!(verify_policy_enforcement(&sel).is_ok());
}

#[test]
fn strict_plus_policy_all_deny() {
    let sel = select_backend(&linux_kvm()).unwrap();
    for grant in &sel.policy.grants {
        assert_eq!(grant.access, AccessLevel::Deny,
                   "strict_plus must deny all: {}", grant.capability);
    }
}

#[test]
fn fallback_chain_maintained() {
    // Even without KVM, we get equivalent isolation
    let sel = select_backend(&linux_no_kvm()).unwrap();
    assert!(sel.backend.is_equivalent());
}

#[test]
fn no_platform_returns_error() {
    let caps = PlatformCapabilities::from_values(
        "unknown", "unknown", false, false, false, false, false, false,
    );
    assert!(select_backend(&caps).is_err());
}

#[test]
fn audit_record_captures_probe() {
    let caps = linux_kvm();
    let sel = select_backend(&caps).unwrap();
    let audit = BackendAuditRecord {
        connector_id: "conn-1".into(),
        selected_backend: sel.backend,
        equivalence: sel.equivalence,
        probe_results: sel.capabilities,
        timestamp: "2026-01-01T00:00:00Z".into(),
    };
    assert_eq!(audit.probe_results.has_kvm, true);
    assert_eq!(audit.selected_backend, IsolationBackend::MicroVm);
}
