//! Integration tests for bd-2k74: Per-peer admission budget enforcement.

use frankenengine_node::connector::admission_budget::*;

fn budget() -> AdmissionBudget {
    AdmissionBudget {
        max_bytes: 10_000,
        max_symbols: 5_000,
        max_failed_auth: 3,
        max_inflight_decode: 5,
        max_decode_cpu_ms: 3_000,
    }
}

fn request(peer: &str, bytes: u64, symbols: u64, cpu: u64) -> AdmissionRequest {
    AdmissionRequest {
        peer_id: peer.into(),
        bytes_requested: bytes,
        symbols_requested: symbols,
        decode_cpu_estimate_ms: cpu,
    }
}

#[test]
fn inv_pab_enforced() {
    let tracker = AdmissionBudgetTracker::new(budget()).unwrap();
    let req = request("p1", 100, 50, 200);
    let (_, records) = tracker.check_admission(&req, "tr", "ts");
    // All 5 dimensions must be checked
    let dims: Vec<&str> = records.iter().map(|r| r.dimension.as_str()).collect();
    assert!(dims.contains(&"bytes"), "INV-PAB-ENFORCED: bytes not checked");
    assert!(dims.contains(&"symbols"), "INV-PAB-ENFORCED: symbols not checked");
    assert!(dims.contains(&"failed_auth"), "INV-PAB-ENFORCED: failed_auth not checked");
    assert!(dims.contains(&"inflight_decode"), "INV-PAB-ENFORCED: inflight_decode not checked");
    assert!(dims.contains(&"decode_cpu"), "INV-PAB-ENFORCED: decode_cpu not checked");
}

#[test]
fn inv_pab_bounded() {
    let mut tracker = AdmissionBudgetTracker::new(budget()).unwrap();
    // Peer exceeds bytes → rejected before processing
    let req = request("p1", 10_001, 0, 0);
    let (verdict, _) = tracker.admit(&req, "tr", "ts");
    assert!(!verdict.admitted, "INV-PAB-BOUNDED: should reject over-budget");
    // Usage should NOT have been updated
    let usage = tracker.get_usage("p1");
    assert_eq!(usage.bytes_used, 0, "INV-PAB-BOUNDED: rejected request must not update usage");
}

#[test]
fn inv_pab_auditable() {
    let tracker = AdmissionBudgetTracker::new(budget()).unwrap();
    let req = request("p1", 100, 50, 200);
    let (verdict, records) = tracker.check_admission(&req, "trace-abc", "2026-01-01");
    assert_eq!(verdict.trace_id, "trace-abc");
    assert_eq!(records.len(), 5);
    for r in &records {
        assert_eq!(r.peer_id, "p1");
        assert_eq!(r.timestamp, "2026-01-01");
        assert!(!r.dimension.is_empty(), "INV-PAB-AUDITABLE: dimension must be labeled");
    }
}

#[test]
fn inv_pab_deterministic() {
    let tracker = AdmissionBudgetTracker::new(budget()).unwrap();
    let req = request("p1", 100, 50, 200);
    let (v1, r1) = tracker.check_admission(&req, "tr", "ts");
    let (v2, r2) = tracker.check_admission(&req, "tr", "ts");
    assert_eq!(v1.admitted, v2.admitted, "INV-PAB-DETERMINISTIC violated");
    assert_eq!(v1.violated_dimensions, v2.violated_dimensions);
    for (a, b) in r1.iter().zip(r2.iter()) {
        assert_eq!(a.dimension, b.dimension);
        assert_eq!(a.verdict, b.verdict);
        assert_eq!(a.usage_before, b.usage_before);
    }
}
