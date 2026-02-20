//! Interface hash verification conformance tests (bd-3n58).
//!
//! Verifies domain separation, fail-closed admission, telemetry
//! recording, and rejection code correctness.

use frankenengine_node::security::interface_hash::*;

#[test]
fn domain_separation_prevents_collision() {
    let h1 = compute_hash("connector.v1", b"payload");
    let h2 = compute_hash("provider.v1", b"payload");
    assert_ne!(h1.hash_hex, h2.hash_hex, "different domains must produce different hashes");
}

#[test]
fn same_domain_same_data_deterministic() {
    let h1 = compute_hash("connector.v1", b"payload");
    let h2 = compute_hash("connector.v1", b"payload");
    assert_eq!(h1, h2);
}

#[test]
fn invalid_hash_blocks_admission() {
    let mut tel = AdmissionTelemetry::new();
    let h = compute_hash("conn.v1", b"data");
    let admitted = tel.admit("conn-1", &h, "conn.v1", b"tampered", "t1", "ts");
    assert!(!admitted, "tampered data must be rejected");
}

#[test]
fn valid_hash_admits() {
    let mut tel = AdmissionTelemetry::new();
    let h = compute_hash("conn.v1", b"data");
    let admitted = tel.admit("conn-1", &h, "conn.v1", b"data", "t2", "ts");
    assert!(admitted);
}

#[test]
fn domain_mismatch_blocks_admission() {
    let mut tel = AdmissionTelemetry::new();
    let h = compute_hash("conn.v1", b"data");
    let admitted = tel.admit("conn-1", &h, "other.v1", b"data", "t3", "ts");
    assert!(!admitted);
    assert_eq!(
        tel.checks[0].rejection_code,
        Some(RejectionCode::DomainMismatch)
    );
}

#[test]
fn telemetry_tracks_every_check() {
    let mut tel = AdmissionTelemetry::new();
    let h = compute_hash("conn.v1", b"data");
    tel.admit("c1", &h, "conn.v1", b"data", "t1", "ts");
    tel.admit("c2", &h, "conn.v1", b"bad", "t2", "ts");
    tel.admit("c3", &h, "conn.v1", b"data", "t3", "ts");
    assert_eq!(tel.total_checks, 3);
    assert_eq!(tel.checks.len(), 3);
}

#[test]
fn telemetry_rejection_distribution_correct() {
    let mut tel = AdmissionTelemetry::new();
    let h = compute_hash("conn.v1", b"data");
    // 2 hash mismatches
    tel.admit("c1", &h, "conn.v1", b"wrong1", "t1", "ts");
    tel.admit("c2", &h, "conn.v1", b"wrong2", "t2", "ts");
    // 1 domain mismatch
    tel.admit("c3", &h, "other.v1", b"data", "t3", "ts");

    assert_eq!(tel.rejection_distribution[&RejectionCode::HashMismatch], 2);
    assert_eq!(tel.rejection_distribution[&RejectionCode::DomainMismatch], 1);
}

#[test]
fn malformed_hash_blocks_admission() {
    let mut tel = AdmissionTelemetry::new();
    let bad_hash = InterfaceHash {
        domain: "conn.v1".into(),
        hash_hex: "ZZZ".into(),
        data_len: 0,
    };
    let admitted = tel.admit("c1", &bad_hash, "conn.v1", b"data", "t4", "ts");
    assert!(!admitted);
    assert_eq!(
        tel.checks[0].rejection_code,
        Some(RejectionCode::MalformedHash)
    );
}

#[test]
fn trace_id_preserved_in_check() {
    let mut tel = AdmissionTelemetry::new();
    let h = compute_hash("conn.v1", b"data");
    tel.admit("c1", &h, "conn.v1", b"data", "trace-xyz", "ts");
    assert_eq!(tel.checks[0].trace_id, "trace-xyz");
}
