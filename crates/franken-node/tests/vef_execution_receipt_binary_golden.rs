//! Golden artifact test for VEF execution receipt binary format
//!
//! Tests that VEF execution receipt canonical binary serialization remains stable
//! across versions. Execution receipts are cryptographically signed audit records
//! and any format change would break signature validation and compliance tooling.

use std::{collections::BTreeMap, fs, path::Path};
use frankenengine_node::connector::vef_execution_receipt::{
    ExecutionReceipt, ExecutionActionType, serialize_canonical, RECEIPT_SCHEMA_VERSION,
};

/// Create a deterministic execution receipt for golden testing
fn create_deterministic_receipt() -> ExecutionReceipt {
    let mut capability_context = BTreeMap::new();
    capability_context.insert("capability".to_string(), "network.egress".to_string());
    capability_context.insert("domain".to_string(), "extensions".to_string());
    capability_context.insert("scope".to_string(), "runtime".to_string());

    ExecutionReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        action_type: ExecutionActionType::NetworkAccess,
        capability_context,
        actor_identity: "agent:golden-test-actor".to_string(),
        artifact_identity: "artifact:ext:franken-node-core-v1.0.0".to_string(),
        policy_snapshot_hash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        timestamp_millis: 1704067200000, // Fixed timestamp: 2024-01-01T00:00:00Z
        sequence_number: 1000,
        witness_references: vec![
            "witness:alpha".to_string(),
            "witness:beta".to_string(),
            "witness:gamma".to_string(),
        ],
        trace_id: "trace-golden-vef-001".to_string(),
    }
}

#[test]
fn vef_execution_receipt_binary_format_golden() {
    let receipt = create_deterministic_receipt();

    // Serialize to canonical binary format
    let binary_output = serialize_canonical(&receipt)
        .expect("VEF execution receipt should serialize to canonical binary");

    let golden_path = Path::new("artifacts/golden/vef_execution_receipt.bin");

    // Check if we're in update mode
    if std::env::var("UPDATE_GOLDENS").is_ok() {
        fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
        fs::write(golden_path, &binary_output).unwrap();
        eprintln!("[GOLDEN] Updated: {}", golden_path.display());
        return;
    }

    // Read expected golden output
    let expected_binary = fs::read(golden_path).unwrap_or_else(|_| {
        panic!(
            "Golden file missing: {}\n\
             Run with UPDATE_GOLDENS=1 to create it\n\
             Then review and commit: git diff artifacts/golden/",
            golden_path.display()
        )
    });

    // Compare byte-for-byte
    if binary_output != expected_binary {
        let actual_path = Path::new("artifacts/golden/vef_execution_receipt.actual.bin");
        fs::write(actual_path, &binary_output).unwrap();

        panic!(
            "GOLDEN MISMATCH: VEF execution receipt binary format changed\n\n\
             This indicates a breaking change to canonical binary serialization\n\
             that could invalidate existing signatures and break audit compliance.\n\n\
             To update: UPDATE_GOLDENS=1 cargo test vef_execution_receipt_binary_format_golden\n\
             To review: xxd {} | head -20 && echo '---' && xxd {} | head -20",
            golden_path.display(),
            actual_path.display(),
        );
    }
}

#[test]
fn vef_execution_receipt_deterministic_serialization() {
    let receipt = create_deterministic_receipt();

    // Multiple serializations should produce identical output
    let output1 = serialize_canonical(&receipt).expect("Should serialize");
    let output2 = serialize_canonical(&receipt).expect("Should serialize");

    assert_eq!(output1, output2, "Canonical serialization must be deterministic");

    // Verify it's valid JSON
    let parsed: serde_json::Value = serde_json::from_slice(&output1)
        .expect("Canonical output should be valid JSON");

    // Verify critical fields are present and correctly serialized
    assert_eq!(parsed["schema_version"], RECEIPT_SCHEMA_VERSION);
    assert_eq!(parsed["action_type"], "network_access");
    assert_eq!(parsed["actor_identity"], "agent:golden-test-actor");
    assert_eq!(parsed["sequence_number"], 1000);
    assert!(parsed["capability_context"].is_object());
    assert!(parsed["witness_references"].is_array());

    // Verify deterministic field ordering (BTreeMap ensures this)
    let context = &parsed["capability_context"];
    let keys: Vec<&str> = context.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, vec!["capability", "domain", "scope"]); // alphabetical order

    // Verify witness references are sorted (canonicalized)
    let witnesses = parsed["witness_references"].as_array().unwrap();
    assert_eq!(witnesses.len(), 3);
    assert_eq!(witnesses[0], "witness:alpha");
    assert_eq!(witnesses[1], "witness:beta");
    assert_eq!(witnesses[2], "witness:gamma");
}