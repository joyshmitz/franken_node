//! Control Plane Fleet Decision Conformance Harness
//!
//! Validates the fleet decision contract end-to-end against specification requirements.

use frankenengine_node::api::fleet_quarantine::{
    DecisionReceipt, DecisionReceiptPayload, QuarantineScope,
    canonical_decision_receipt_payload_hash, verify_decision_receipt_signature,
};

#[test]
fn test_decision_receipt_quarantine_creation() {
    // MUST: Create valid quarantine decision receipt
    let payload = DecisionReceiptPayload::quarantine("test-extension", &QuarantineScope::Global);
    assert_eq!(payload.extension_id, "test-extension");
    assert!(!payload.timestamp.is_empty());
    assert!(!payload.receipt_id.is_empty());
}

#[test]
fn test_decision_receipt_payload_hash() {
    // MUST: Payload hash must be deterministic and non-empty
    let payload = DecisionReceiptPayload::quarantine("test-ext", &QuarantineScope::Global);
    let hash1 = canonical_decision_receipt_payload_hash(&payload);
    let hash2 = canonical_decision_receipt_payload_hash(&payload);

    assert!(!hash1.is_empty());
    assert_eq!(hash1, hash2, "Hash must be deterministic");
}

#[test]
fn test_decision_receipt_different_inputs_different_hashes() {
    // MUST: Different payloads must produce different hashes
    let payload1 = DecisionReceiptPayload::quarantine("ext-1", &QuarantineScope::Global);
    let payload2 = DecisionReceiptPayload::quarantine("ext-2", &QuarantineScope::Global);

    let hash1 = canonical_decision_receipt_payload_hash(&payload1);
    let hash2 = canonical_decision_receipt_payload_hash(&payload2);

    assert_ne!(hash1, hash2, "Different payloads must produce different hashes");
}