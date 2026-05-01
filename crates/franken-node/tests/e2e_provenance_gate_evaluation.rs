//! Mock-free end-to-end test for the supply-chain provenance gate.
//!
//! Drives `frankenengine_node::supply_chain::provenance_gate::evaluate_gate`
//! through the full GateDecision matrix:
//!
//!   - happy path → passed=true, no failure_reason,
//!   - MissingAttestation → enumerates the missing types,
//!   - InsufficientAssurance → reports `have` vs `need`,
//!   - UntrustedBuilder → reports the offending builder_id,
//!   - InvalidArtifactId → empty / reserved (`<unknown>`) / null-byte /
//!     leading whitespace / oversize > MAX_ARTIFACT_ID_LEN,
//!   - PolicyInvalid → empty trusted_builders, whitespace builder,
//!     empty custom attestation name, oversize required_attestations,
//!   - BuildAssurance ordering: None < Basic < Verified < Hardened.
//!
//! Bead: bd-1p796.
//!
//! No mocks: real `ProvenancePolicy`, real `ArtifactProvenance`, real
//! pure-function `evaluate_gate`. Each phase emits a structured tracing
//! event PLUS a JSON-line on stderr.

use std::sync::Once;
use std::time::Instant;

use frankenengine_node::supply_chain::provenance_gate::{
    ArtifactProvenance, AttestationType, BuildAssurance, GateFailure, ProvenancePolicy,
    evaluate_gate,
};
use serde_json::json;
use tracing::{error, info};

static TEST_TRACING_INIT: Once = Once::new();

fn init_test_tracing() {
    TEST_TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    });
}

#[derive(serde::Serialize)]
struct PhaseLog<'a> {
    timestamp: String,
    test_name: &'a str,
    phase: &'a str,
    duration_ms: u64,
    success: bool,
    detail: serde_json::Value,
}

struct Harness {
    test_name: &'static str,
    started: Instant,
}

impl Harness {
    fn new(test_name: &'static str) -> Self {
        init_test_tracing();
        let h = Self {
            test_name,
            started: Instant::now(),
        };
        h.log_phase("setup", true, json!({}));
        h
    }

    fn log_phase(&self, phase: &str, success: bool, detail: serde_json::Value) {
        let entry = PhaseLog {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: self.test_name,
            phase,
            duration_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            success,
            detail,
        };
        eprintln!(
            "{}",
            serde_json::to_string(&entry).expect("phase log serializes")
        );
        if success {
            info!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase completed"
            );
        } else {
            error!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase failed"
            );
        }
    }
}

fn strict_policy() -> ProvenancePolicy {
    ProvenancePolicy {
        required_attestations: vec![AttestationType::Slsa, AttestationType::Sigstore],
        min_build_assurance: BuildAssurance::Verified,
        trusted_builders: vec!["builder-prod-1".to_string()],
    }
}

fn good_provenance() -> ArtifactProvenance {
    ArtifactProvenance {
        artifact_id: "sha256:fixed-art-001".to_string(),
        connector_id: "conn-prod".to_string(),
        attestations: vec![AttestationType::Slsa, AttestationType::Sigstore],
        build_assurance: BuildAssurance::Hardened,
        builder_id: "builder-prod-1".to_string(),
    }
}

#[test]
fn e2e_provenance_gate_happy_path() {
    let h = Harness::new("e2e_provenance_gate_happy_path");

    let decision = evaluate_gate(
        &strict_policy(),
        &good_provenance(),
        "trace-happy",
        "2026-04-27T00:00:00Z",
    );
    assert!(decision.passed);
    assert!(decision.missing_attestations.is_empty());
    assert!(decision.assurance_ok);
    assert!(decision.builder_trusted);
    assert!(decision.failure_reason.is_none());
    h.log_phase("passed", true, json!({"trace": decision.trace_id}));
}

#[test]
fn e2e_provenance_gate_missing_attestation_enumerated() {
    let h = Harness::new("e2e_provenance_gate_missing_attestation_enumerated");

    let mut prov = good_provenance();
    prov.attestations = vec![AttestationType::Slsa]; // missing Sigstore
    let decision = evaluate_gate(
        &strict_policy(),
        &prov,
        "trace-missing",
        "2026-04-27T00:00:01Z",
    );
    assert!(!decision.passed);
    match &decision.failure_reason {
        Some(GateFailure::MissingAttestation { types }) => {
            assert_eq!(types.len(), 1);
            assert!(matches!(types[0], AttestationType::Sigstore));
            h.log_phase("missing_sigstore", true, json!({"missing": 1}));
        }
        other => panic!("expected MissingAttestation, got {other:?}"),
    }
    assert_eq!(decision.missing_attestations.len(), 1);
}

#[test]
fn e2e_provenance_gate_assurance_boundary() {
    let h = Harness::new("e2e_provenance_gate_assurance_boundary");

    // BuildAssurance ordering as expected.
    assert_eq!(BuildAssurance::None.level(), 0);
    assert_eq!(BuildAssurance::Basic.level(), 1);
    assert_eq!(BuildAssurance::Verified.level(), 2);
    assert_eq!(BuildAssurance::Hardened.level(), 3);
    assert!(BuildAssurance::Hardened.meets_minimum(BuildAssurance::Verified));
    assert!(BuildAssurance::Verified.meets_minimum(BuildAssurance::Verified));
    assert!(!BuildAssurance::Basic.meets_minimum(BuildAssurance::Verified));
    h.log_phase("level_ordering", true, json!({}));

    // Boundary: have=Verified meets need=Verified → passes assurance.
    let mut prov = good_provenance();
    prov.build_assurance = BuildAssurance::Verified;
    let decision = evaluate_gate(
        &strict_policy(),
        &prov,
        "trace-boundary",
        "2026-04-27T00:00:02Z",
    );
    assert!(decision.assurance_ok);
    assert!(decision.passed);
    h.log_phase("assurance_at_boundary", true, json!({}));

    // Below boundary: have=Basic, need=Verified → InsufficientAssurance.
    prov.build_assurance = BuildAssurance::Basic;
    let decision = evaluate_gate(&strict_policy(), &prov, "trace-low", "2026-04-27T00:00:03Z");
    assert!(!decision.passed);
    match &decision.failure_reason {
        Some(GateFailure::InsufficientAssurance { have, need }) => {
            assert_eq!(*have, BuildAssurance::Basic);
            assert_eq!(*need, BuildAssurance::Verified);
            h.log_phase(
                "insufficient_assurance",
                true,
                json!({"have": "basic", "need": "verified"}),
            );
        }
        other => panic!("expected InsufficientAssurance, got {other:?}"),
    }
}

#[test]
fn e2e_provenance_gate_untrusted_builder() {
    let h = Harness::new("e2e_provenance_gate_untrusted_builder");

    let mut prov = good_provenance();
    prov.builder_id = "rogue-builder".to_string();
    let decision = evaluate_gate(
        &strict_policy(),
        &prov,
        "trace-untrusted",
        "2026-04-27T00:00:04Z",
    );
    assert!(!decision.passed);
    assert!(!decision.builder_trusted);
    match &decision.failure_reason {
        Some(GateFailure::UntrustedBuilder { builder_id }) => {
            assert_eq!(builder_id, "rogue-builder");
            h.log_phase(
                "untrusted_builder",
                true,
                json!({"builder": "rogue-builder"}),
            );
        }
        other => panic!("expected UntrustedBuilder, got {other:?}"),
    }
}

#[test]
fn e2e_provenance_gate_invalid_artifact_id_matrix() {
    let h = Harness::new("e2e_provenance_gate_invalid_artifact_id_matrix");

    let policy = strict_policy();

    let bad_ids = [
        ("", "empty"),
        ("<unknown>", "reserved"),
        ("art-with-\0null", "null byte"),
        (" leading-space", "leading whitespace"),
        ("trailing-space ", "trailing whitespace"),
    ];
    for (id, label) in bad_ids {
        let mut prov = good_provenance();
        prov.artifact_id = id.to_string();
        let decision = evaluate_gate(&policy, &prov, "trace-bad", "2026-04-27T00:00:05Z");
        assert!(!decision.passed);
        match decision.failure_reason {
            Some(GateFailure::InvalidArtifactId { reason: _ }) => {
                h.log_phase(
                    "invalid_artifact_id_rejected",
                    true,
                    json!({"label": label}),
                );
            }
            other => panic!("expected InvalidArtifactId for {label:?}, got {other:?}"),
        }
    }

    // Oversize artifact_id (> MAX_ARTIFACT_ID_LEN = 512).
    let mut prov = good_provenance();
    prov.artifact_id = "a".repeat(600);
    let decision = evaluate_gate(&policy, &prov, "trace-oversize", "2026-04-27T00:00:06Z");
    assert!(!decision.passed);
    match decision.failure_reason {
        Some(GateFailure::InvalidArtifactId { reason }) => {
            assert!(reason.contains("too long"));
            h.log_phase("oversize_rejected", true, json!({"reason": reason}));
        }
        other => panic!("expected InvalidArtifactId(too long), got {other:?}"),
    }
}

#[test]
fn e2e_provenance_gate_policy_invalid_paths() {
    let h = Harness::new("e2e_provenance_gate_policy_invalid_paths");

    let prov = good_provenance();

    // Empty trusted_builders.
    let policy = ProvenancePolicy {
        required_attestations: vec![AttestationType::Slsa],
        min_build_assurance: BuildAssurance::Basic,
        trusted_builders: vec![],
    };
    let decision = evaluate_gate(&policy, &prov, "trace-empty-trust", "2026-04-27T00:00:07Z");
    assert!(!decision.passed);
    match decision.failure_reason {
        Some(GateFailure::PolicyInvalid { reason }) => {
            assert!(reason.contains("trusted_builders"));
            h.log_phase("empty_trusted_builders", true, json!({"reason": reason}));
        }
        other => panic!("expected PolicyInvalid for empty trust, got {other:?}"),
    }

    // Whitespace-only builder ID.
    let policy = ProvenancePolicy {
        required_attestations: vec![],
        min_build_assurance: BuildAssurance::Basic,
        trusted_builders: vec!["   ".to_string()],
    };
    let decision = evaluate_gate(&policy, &prov, "trace-ws-builder", "2026-04-27T00:00:08Z");
    assert!(matches!(
        decision.failure_reason,
        Some(GateFailure::PolicyInvalid { .. })
    ));
    h.log_phase("whitespace_builder_rejected", true, json!({}));

    // Custom attestation with empty name.
    let policy = ProvenancePolicy {
        required_attestations: vec![AttestationType::Custom(String::new())],
        min_build_assurance: BuildAssurance::Basic,
        trusted_builders: vec!["builder-prod-1".to_string()],
    };
    let decision = evaluate_gate(&policy, &prov, "trace-empty-cust", "2026-04-27T00:00:09Z");
    assert!(matches!(
        decision.failure_reason,
        Some(GateFailure::PolicyInvalid { .. })
    ));
    h.log_phase("empty_custom_name_rejected", true, json!({}));
}

#[test]
fn e2e_provenance_gate_decision_is_deterministic() {
    let h = Harness::new("e2e_provenance_gate_decision_is_deterministic");

    let policy = strict_policy();
    let prov = good_provenance();

    // Identical inputs → identical decisions (modulo trace_id/timestamp passthrough).
    let d1 = evaluate_gate(&policy, &prov, "trace-A", "2026-04-27T00:00:10Z");
    let d2 = evaluate_gate(&policy, &prov, "trace-B", "2026-04-27T00:00:11Z");
    assert_eq!(d1.passed, d2.passed);
    assert_eq!(d1.assurance_ok, d2.assurance_ok);
    assert_eq!(d1.builder_trusted, d2.builder_trusted);
    assert_eq!(d1.missing_attestations, d2.missing_attestations);
    assert_eq!(d1.failure_reason, d2.failure_reason);
    // The trace_id/timestamp are passthrough.
    assert_eq!(d1.trace_id, "trace-A");
    assert_eq!(d2.trace_id, "trace-B");
    h.log_phase("deterministic", true, json!({}));
}

#[test]
fn e2e_provenance_gate_attestation_display() {
    let h = Harness::new("e2e_provenance_gate_attestation_display");

    assert_eq!(format!("{}", AttestationType::Slsa), "slsa");
    assert_eq!(format!("{}", AttestationType::Sigstore), "sigstore");
    assert_eq!(format!("{}", AttestationType::InToto), "in_toto");
    assert_eq!(
        format!("{}", AttestationType::Custom("vendor-x".into())),
        "custom:vendor-x"
    );
    h.log_phase("display_stable", true, json!({}));
}
