//! Attestation/provenance gate security tests (bd-3i9o).
//!
//! Verifies that policy gates enforce required attestations, build
//! assurance minimums, and trusted builder constraints.

use frankenengine_node::supply_chain::provenance_gate::*;

fn policy() -> ProvenancePolicy {
    ProvenancePolicy {
        required_attestations: vec![AttestationType::Slsa, AttestationType::Sigstore],
        min_build_assurance: BuildAssurance::Verified,
        trusted_builders: vec!["builder-alpha".into(), "builder-beta".into()],
    }
}

fn compliant_artifact() -> ArtifactProvenance {
    ArtifactProvenance {
        artifact_id: "art-test".into(),
        connector_id: "conn-test".into(),
        attestations: vec![AttestationType::Slsa, AttestationType::Sigstore],
        build_assurance: BuildAssurance::Hardened,
        builder_id: "builder-alpha".into(),
    }
}

#[test]
fn compliant_artifact_passes() {
    let result = evaluate_gate(&policy(), &compliant_artifact(), "t1", "ts");
    assert!(result.passed);
}

#[test]
fn missing_slsa_blocks() {
    let mut prov = compliant_artifact();
    prov.attestations = vec![AttestationType::Sigstore];
    let result = evaluate_gate(&policy(), &prov, "t2", "ts");
    assert!(!result.passed);
    assert!(result.missing_attestations.contains(&AttestationType::Slsa));
}

#[test]
fn low_assurance_blocks() {
    let mut prov = compliant_artifact();
    prov.build_assurance = BuildAssurance::Basic;
    let result = evaluate_gate(&policy(), &prov, "t3", "ts");
    assert!(!result.passed);
    assert!(!result.assurance_ok);
}

#[test]
fn untrusted_builder_blocks() {
    let mut prov = compliant_artifact();
    prov.builder_id = "evil-builder".into();
    let result = evaluate_gate(&policy(), &prov, "t4", "ts");
    assert!(!result.passed);
    assert!(!result.builder_trusted);
}

#[test]
fn non_compliant_blocked_pre_activation() {
    let prov = ArtifactProvenance {
        artifact_id: "art-bad".into(),
        connector_id: "conn-bad".into(),
        attestations: vec![],
        build_assurance: BuildAssurance::None,
        builder_id: "unknown".into(),
    };
    let result = evaluate_gate(&policy(), &prov, "t5", "ts");
    assert!(!result.passed);
    assert!(!result.missing_attestations.is_empty());
    assert!(!result.assurance_ok);
    assert!(!result.builder_trusted);
}

#[test]
fn gate_result_has_trace_id() {
    let result = evaluate_gate(&policy(), &compliant_artifact(), "trace-abc", "ts");
    assert_eq!(result.trace_id, "trace-abc");
}

#[test]
fn custom_attestation_type_supported() {
    let mut pol = policy();
    pol.required_attestations.push(AttestationType::Custom("sbom".into()));
    let mut prov = compliant_artifact();
    prov.attestations.push(AttestationType::Custom("sbom".into()));
    let result = evaluate_gate(&pol, &prov, "t6", "ts");
    assert!(result.passed);
}
