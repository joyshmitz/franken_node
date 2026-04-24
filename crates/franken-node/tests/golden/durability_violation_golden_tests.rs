//! Golden artifact tests for durability violation bundle outputs.
//!
//! Ensures deterministic JSON output format for diagnostic bundles
//! to prevent regressions in monitoring and alerting systems.

use std::path::PathBuf;
use frankenengine_node::observability::durability_violation::{
    DurabilityViolationDetector, DurabilityViolationContext, CausalEvent, CausalEventType,
    FailedArtifact, ProofContext, HaltPolicy,
};
use serde_json::Value;

// Golden utilities re-exported from parent module
use super::{assert_golden, assert_json_golden, golden_path_for};

/// Create a deterministic test context for golden comparison.
fn create_test_violation_context() -> DurabilityViolationContext {
    let mut ctx = DurabilityViolationContext::new(
        1000, // Fixed epoch_id
        2000, // Fixed timestamp_ms
        "test-hardening-level".to_string(),
    );

    // Add deterministic causal events
    ctx.add_causal_event(CausalEvent {
        event_type: CausalEventType::GuardrailRejection,
        timestamp_ms: 1500,
        description: "Test guardrail rejection event".to_string(),
        evidence_ref: Some("EVD-TEST-001".to_string()),
    });

    ctx.add_causal_event(CausalEvent {
        event_type: CausalEventType::IntegrityCheckFailed,
        timestamp_ms: 1800,
        description: "Test integrity check failure".to_string(),
        evidence_ref: None,
    });

    // Add deterministic failed artifacts
    ctx.add_failed_artifact(FailedArtifact {
        artifact_path: "objects/test-artifact-001".to_string(),
        expected_hash: "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678".to_string(),
        actual_hash: "cafebabe1234567890abcdef1234567890abcdef1234567890abcdef12345678".to_string(),
        failure_reason: "Test hash mismatch".to_string(),
    });

    ctx.add_failed_artifact(FailedArtifact {
        artifact_path: "signatures/test-signature.sig".to_string(),
        expected_hash: "facefeed1234567890abcdef1234567890abcdef1234567890abcdef12345678".to_string(),
        actual_hash: "".to_string(),
        failure_reason: "Test missing artifact".to_string(),
    });

    // Add deterministic proof context
    ctx.proofs.add_missing_proof("proof-test-001".to_string());
    ctx.proofs.add_invalid_proof("proof-test-002".to_string(), "Test validation failed".to_string());

    ctx
}

#[test]
fn durability_violation_bundle_json_output() {
    let ctx = create_test_violation_context();
    let detector = DurabilityViolationDetector::new(HaltPolicy::HaltAll);
    let bundle = detector.generate_bundle(&ctx);

    let json_output = bundle.to_json();
    let parsed: Value = serde_json::from_str(&json_output)
        .expect("Bundle JSON should be valid");

    assert_json_golden("durability_violation_bundle", &parsed);
}

#[test]
fn durability_violation_bundle_minimal_context() {
    // Test with minimal context to ensure clean output
    let mut ctx = DurabilityViolationContext::new(
        42, // Fixed epoch_id
        5000, // Fixed timestamp_ms
        "critical".to_string(),
    );

    ctx.add_causal_event(CausalEvent {
        event_type: CausalEventType::ArtifactUnverifiable,
        timestamp_ms: 4500,
        description: "Single test event".to_string(),
        evidence_ref: None,
    });

    let detector = DurabilityViolationDetector::new(HaltPolicy::WarnOnly);
    let bundle = detector.generate_bundle(&ctx);

    let json_output = bundle.to_json();
    let parsed: Value = serde_json::from_str(&json_output)
        .expect("Minimal bundle JSON should be valid");

    assert_json_golden("durability_violation_minimal", &parsed);
}

#[test]
fn durability_violation_bundle_escaping_test() {
    // Test proper JSON escaping of special characters
    let mut ctx = DurabilityViolationContext::new(
        999, // Fixed epoch_id
        7000, // Fixed timestamp_ms
        "level with \"quotes\" and\nnewlines".to_string(),
    );

    ctx.add_causal_event(CausalEvent {
        event_type: CausalEventType::RepairFailed,
        timestamp_ms: 6500,
        description: "Event with \"quotes\" and\ntabs\tand backslashes\\".to_string(),
        evidence_ref: Some("EVD-\"escape\"-test".to_string()),
    });

    ctx.add_failed_artifact(FailedArtifact {
        artifact_path: "path/with spaces/and\"quotes\".bin".to_string(),
        expected_hash: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        actual_hash: "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        failure_reason: "Reason with \"quotes\" and\nnewlines and tabs\t".to_string(),
    });

    let detector = DurabilityViolationDetector::new(HaltPolicy::HaltScope("test-scope".to_string()));
    let bundle = detector.generate_bundle(&ctx);

    let json_output = bundle.to_json();
    let parsed: Value = serde_json::from_str(&json_output)
        .expect("Escaping bundle JSON should be valid");

    assert_json_golden("durability_violation_escaping", &parsed);
}