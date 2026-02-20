//! Integration tests for bd-3b8m: Anti-amplification response bounds.

use frankenengine_node::connector::anti_amplification::*;

fn policy() -> AmplificationPolicy {
    AmplificationPolicy {
        max_response_ratio: 10.0,
        unauth_max_bytes: 1_000,
        auth_max_bytes: 10_000,
        max_items_per_response: 50,
    }
}

fn bound(bytes: u64, items: u32) -> ResponseBound {
    ResponseBound { max_bytes: bytes, max_items: items }
}

fn req(id: &str, peer: &str, auth: bool, req_bytes: u64, decl_bytes: u64, actual: u64, items: u32) -> BoundCheckRequest {
    BoundCheckRequest {
        request_id: id.into(),
        peer_id: peer.into(),
        authenticated: auth,
        request_bytes: req_bytes,
        declared_bound: bound(decl_bytes, 50),
        actual_response_bytes: actual,
        actual_items: items,
    }
}

#[test]
fn inv_aar_bounded() {
    let r = req("r1", "p1", true, 100, 5000, 6000, 10);
    let (v, _) = check_response_bound(&r, &policy(), "tr", "ts").unwrap();
    assert!(!v.allowed, "INV-AAR-BOUNDED: response exceeding declared bound must be blocked");
    assert!(v.enforced_limit <= 5000, "INV-AAR-BOUNDED: enforced limit must respect declared bound");
}

#[test]
fn inv_aar_unauth_strict() {
    let p = policy();
    let unauth = enforced_limit(&p, &bound(50000, 50), false);
    let auth = enforced_limit(&p, &bound(50000, 50), true);
    assert!(unauth < auth, "INV-AAR-UNAUTH-STRICT: unauth limit must be stricter than auth");

    // Unauth peer at auth-level bytes → blocked
    let r = req("r1", "p1", false, 100, 50000, 5000, 10);
    let (v, _) = check_response_bound(&r, &p, "tr", "ts").unwrap();
    assert!(!v.allowed, "INV-AAR-UNAUTH-STRICT: unauth peer above strict limit must be blocked");
}

#[test]
fn inv_aar_auditable() {
    let r = req("r1", "p1", true, 100, 5000, 500, 10);
    let (v, audit) = check_response_bound(&r, &policy(), "trace-xyz", "2026-01-15").unwrap();
    assert_eq!(v.trace_id, "trace-xyz");
    assert_eq!(audit.request_id, "r1");
    assert_eq!(audit.peer_id, "p1");
    assert_eq!(audit.timestamp, "2026-01-15");
    assert!(!audit.verdict.is_empty(), "INV-AAR-AUDITABLE: verdict must be present");
}

#[test]
fn inv_aar_deterministic() {
    let r = req("r1", "p1", true, 100, 5000, 500, 10);
    let (v1, a1) = check_response_bound(&r, &policy(), "tr", "ts").unwrap();
    let (v2, a2) = check_response_bound(&r, &policy(), "tr", "ts").unwrap();
    assert_eq!(v1.allowed, v2.allowed, "INV-AAR-DETERMINISTIC: same inputs must give same verdict");
    assert_eq!(v1.enforced_limit, v2.enforced_limit);
    assert_eq!(a1.verdict, a2.verdict);
    assert_eq!(a1.ratio, a2.ratio);
}
