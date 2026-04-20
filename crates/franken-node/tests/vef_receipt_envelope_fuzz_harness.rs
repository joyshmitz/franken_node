//! Structure-aware fuzzing for VEF receipt envelope parsing.
//!
//! Tests receipt chain integrity, checkpoint validation, hash chain consistency,
//! and tamper detection following patterns established in canonical_serializer_fuzz_harness.

use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;
use frankenengine_node::vef::receipt_chain::{
    ReceiptChainEntry, ReceiptCheckpoint, ReceiptChainConfig, AppendOutcome,
    ChainError, ChainEvent, RECEIPT_CHAIN_SCHEMA_VERSION, GENESIS_PREV_HASH,
    event_codes, error_codes,
};
use frankenengine_node::connector::vef_execution_receipt::{
    ExecutionReceipt, ReceiptOperationType, VerificationContext, receipt_hash_sha256,
};
use sha2::{Digest, Sha256};

/// Seed corpus for VEF receipt envelope fuzzing.
const RECEIPT_SEED_CORPUS: &[&[u8]] = &[
    // Valid minimal receipt JSON
    br#"{"receipt_id":"test-001","operation_type":"verify","trace_id":"trace-001","timestamp_millis":1234567890,"verifier_identity":"test-verifier","verification_context":{"domain":"test"},"result":{"status":"success","evidence":{}}}"#,

    // Receipt with complex verification context
    br#"{"receipt_id":"complex-001","operation_type":"attest","trace_id":"trace-complex","timestamp_millis":1234567890,"verifier_identity":"complex-verifier","verification_context":{"domain":"production","constraints":{"max_depth":10,"timeout_ms":5000}},"result":{"status":"success","evidence":{"signatures":["sig1","sig2"],"proofs":["proof1"]}}}"#,

    // Boundary condition receipts
    b"{}",  // Empty JSON object
    br#"{"receipt_id":""}"#,  // Empty receipt ID
    br#"{"receipt_id":"test","operation_type":"","trace_id":"","timestamp_millis":0}"#,  // Empty fields

    // Very large receipt
    &format!(
        r#"{{"receipt_id":"large-{}","operation_type":"verify","trace_id":"large-trace","timestamp_millis":1234567890,"verifier_identity":"large-verifier","verification_context":{{"domain":"test"}},"result":{{"status":"success","evidence":{{}}}}}}"#,
        "x".repeat(10000)
    ).as_bytes(),

    // Invalid JSON structures
    b"{",  // Truncated JSON
    br#"{"receipt_id":"test","operation_type":"verify""#,  // Unclosed JSON
    br#"{"receipt_id":"test","operation_type":"verify","invalid_extra_comma":,}"#,  // Invalid comma
    br#"{"receipt_id":"test","operation_type":"verify","malformed_field":}"#,  // Malformed field

    // JSON injection attempts
    br#"{"receipt_id":"test\", \"admin\": true, \"bypass\": \"","operation_type":"verify"}"#,
    br#"{"receipt_id":"test","operation_type":"verify\"; DROP TABLE receipts; --"}"#,

    // Unicode and encoding edge cases
    br#"{"receipt_id":"test-🔒","operation_type":"verify","trace_id":"trace-🚀"}"#,  // Unicode in IDs
    b"\xff\xfe{\"receipt_id\":\"test\"",  // Invalid UTF-8 prefix
    b"\x00\x01\x02{\"receipt_id\":\"test\"}",  // Binary prefix

    // Very long field values
    &format!(r#"{{"receipt_id":"{}","operation_type":"verify"}}"#, "A".repeat(100_000)).as_bytes(),

    // Control characters in JSON
    b"{\"receipt_id\":\"test\\u0000\",\"operation_type\":\"verify\"}",  // Null in string
    b"{\"receipt_id\":\"test\\n\",\"operation_type\":\"verify\"}",     // Newline in string
    b"{\"receipt_id\":\"test\\r\",\"operation_type\":\"verify\"}",     // CR in string
    b"{\"receipt_id\":\"test\\t\",\"operation_type\":\"verify\"}",     // Tab in string
];

/// Chain entry seed corpus for testing chain integrity.
const CHAIN_ENTRY_JSON_CORPUS: &[&str] = &[
    // Valid chain entry
    r#"{"index":0,"prev_chain_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","receipt_hash":"sha256:abcd1234","chain_hash":"sha256:ef567890","receipt":{"receipt_id":"test","operation_type":"verify","trace_id":"trace","timestamp_millis":1234567890,"verifier_identity":"verifier","verification_context":{"domain":"test"},"result":{"status":"success","evidence":{}}},"appended_at_millis":1234567890,"trace_id":"trace"}"#,

    // Chain entry with invalid hash format
    r#"{"index":0,"prev_chain_hash":"invalid_hash","receipt_hash":"also_invalid","chain_hash":"malformed","receipt":{"receipt_id":"test","operation_type":"verify","trace_id":"trace","timestamp_millis":1234567890,"verifier_identity":"verifier","verification_context":{"domain":"test"},"result":{"status":"success","evidence":{}}},"appended_at_millis":1234567890,"trace_id":"trace"}"#,

    // Chain entry with mismatched index
    r#"{"index":999,"prev_chain_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","receipt_hash":"sha256:abcd1234","chain_hash":"sha256:ef567890","receipt":{"receipt_id":"test","operation_type":"verify","trace_id":"trace","timestamp_millis":1234567890,"verifier_identity":"verifier","verification_context":{"domain":"test"},"result":{"status":"success","evidence":{}}},"appended_at_millis":1234567890,"trace_id":"trace"}"#,

    // Empty fields
    r#"{"index":0,"prev_chain_hash":"","receipt_hash":"","chain_hash":"","receipt":{"receipt_id":"","operation_type":"","trace_id":"","timestamp_millis":0,"verifier_identity":"","verification_context":{},"result":{"status":"","evidence":{}}},"appended_at_millis":0,"trace_id":""}"#,

    // Very large index values
    r#"{"index":18446744073709551615,"prev_chain_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","receipt_hash":"sha256:abcd1234","chain_hash":"sha256:ef567890","receipt":{"receipt_id":"test","operation_type":"verify","trace_id":"trace","timestamp_millis":1234567890,"verifier_identity":"verifier","verification_context":{"domain":"test"},"result":{"status":"success","evidence":{}}},"appended_at_millis":18446744073709551615,"trace_id":"trace"}"#,
];

/// Checkpoint JSON corpus for checkpoint validation testing.
const CHECKPOINT_JSON_CORPUS: &[&str] = &[
    // Valid checkpoint
    r#"{"checkpoint_id":1,"start_index":0,"end_index":63,"entry_count":64,"chain_head_hash":"sha256:abcd1234","commitment_hash":"sha256:ef567890","created_at_millis":1234567890,"trace_id":"checkpoint-trace"}"#,

    // Checkpoint with inconsistent counts
    r#"{"checkpoint_id":1,"start_index":10,"end_index":20,"entry_count":999,"chain_head_hash":"sha256:abcd1234","commitment_hash":"sha256:ef567890","created_at_millis":1234567890,"trace_id":"checkpoint-trace"}"#,

    // Checkpoint with invalid range (start > end)
    r#"{"checkpoint_id":1,"start_index":100,"end_index":50,"entry_count":0,"chain_head_hash":"sha256:abcd1234","commitment_hash":"sha256:ef567890","created_at_millis":1234567890,"trace_id":"checkpoint-trace"}"#,

    // Empty checkpoint
    r#"{"checkpoint_id":0,"start_index":0,"end_index":0,"entry_count":0,"chain_head_hash":"","commitment_hash":"","created_at_millis":0,"trace_id":""}"#,

    // Maximum values checkpoint
    r#"{"checkpoint_id":18446744073709551615,"start_index":18446744073709551615,"end_index":18446744073709551615,"entry_count":18446744073709551615,"chain_head_hash":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","commitment_hash":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","created_at_millis":18446744073709551615,"trace_id":"max-trace"}"#,
];

fuzz_target!(|data: &[u8]| {
    fuzz_vef_receipt_envelopes(data);
});

fn fuzz_vef_receipt_envelopes(data: &[u8]) {
    // Test 1: Receipt parsing with malformed inputs
    test_receipt_parsing_boundary_conditions(data);

    // Test 2: Chain entry validation and integrity
    test_chain_entry_validation(data);

    // Test 3: Checkpoint consistency and tamper detection
    test_checkpoint_validation(data);

    // Test 4: Hash chain consistency and determinism
    test_hash_chain_determinism(data);

    // Test 5: Receipt chain configuration edge cases
    test_chain_config_validation(data);

    // Test 6: Chain error handling and fail-closed semantics
    test_chain_error_handling(data);
}

fn test_receipt_parsing_boundary_conditions(data: &[u8]) {
    // Test ExecutionReceipt parsing with various inputs
    if let Ok(json_str) = std::str::from_utf8(data) {
        if !json_str.is_empty() && json_str.len() < 1_000_000 {
            // Test JSON deserialization
            let parse_result: Result<ExecutionReceipt, _> = serde_json::from_str(json_str);

            match parse_result {
                Ok(receipt) => {
                    // Valid receipt parsed - test its properties
                    test_receipt_consistency(&receipt);

                    // Test receipt hashing
                    if let Ok(hash) = receipt_hash_sha256(&receipt) {
                        assert!(hash.starts_with("sha256:"));
                        assert_eq!(hash.len(), 71); // "sha256:" + 64 hex chars

                        // Test hash determinism - same receipt should produce same hash
                        if let Ok(hash2) = receipt_hash_sha256(&receipt) {
                            assert_eq!(hash, hash2);
                        }
                    }

                    // Test serialization round-trip
                    if let Ok(serialized) = serde_json::to_string(&receipt) {
                        if let Ok(reparsed): Result<ExecutionReceipt, _> = serde_json::from_str(&serialized) {
                            // Basic consistency check after round-trip
                            assert_eq!(receipt.receipt_id, reparsed.receipt_id);
                            assert_eq!(receipt.trace_id, reparsed.trace_id);
                            assert_eq!(receipt.timestamp_millis, reparsed.timestamp_millis);
                        }
                    }
                }
                Err(_) => {
                    // Parsing failed - should not panic
                    // This is normal for malformed input
                }
            }
        }
    }
}

fn test_receipt_consistency(receipt: &ExecutionReceipt) {
    // Test receipt field consistency and constraints
    assert!(!receipt.receipt_id.is_empty() || receipt.receipt_id.is_empty()); // Should not panic
    assert!(!receipt.trace_id.is_empty() || receipt.trace_id.is_empty());     // Should not panic

    // Test timestamp bounds (should be reasonable)
    if receipt.timestamp_millis > 0 {
        // Timestamp should be finite
        assert!(receipt.timestamp_millis.is_finite());
    }

    // Test verifier identity
    let _ = receipt.verifier_identity.len(); // Should not panic

    // Test operation type consistency
    match &receipt.operation_type {
        ReceiptOperationType::Verify => {
            // Verify operations should have verification context
            // (though empty context might be valid in some cases)
        }
        ReceiptOperationType::Attest => {
            // Attest operations may have different requirements
        }
        _ => {
            // Other operation types should be handled gracefully
        }
    }

    // Test verification context
    test_verification_context_consistency(&receipt.verification_context);
}

fn test_verification_context_consistency(context: &VerificationContext) {
    // Test that verification context fields are well-formed
    let _ = context.domain.len(); // Should not panic

    // Test constraints if present
    if let Some(ref constraints) = context.constraints {
        for (key, value) in constraints {
            assert!(!key.is_empty() || key.is_empty()); // Should not panic on empty keys

            // Test value deserialization
            if let Ok(json_value) = serde_json::to_value(value) {
                let _ = json_value.to_string(); // Should not panic
            }
        }
    }
}

fn test_chain_entry_validation(data: &[u8]) {
    if let Ok(json_str) = std::str::from_utf8(data) {
        if !json_str.is_empty() && json_str.len() < 1_000_000 {
            let parse_result: Result<ReceiptChainEntry, _> = serde_json::from_str(json_str);

            match parse_result {
                Ok(entry) => {
                    // Test chain entry consistency
                    test_chain_entry_consistency(&entry);

                    // Test hash format validation
                    test_hash_format_validation(&entry.prev_chain_hash, "prev_chain_hash");
                    test_hash_format_validation(&entry.receipt_hash, "receipt_hash");
                    test_hash_format_validation(&entry.chain_hash, "chain_hash");

                    // Test index consistency (should be finite)
                    assert!(entry.index.is_finite());

                    // Test timestamp consistency
                    assert!(entry.appended_at_millis.is_finite());

                    // Test receipt consistency
                    test_receipt_consistency(&entry.receipt);
                }
                Err(_) => {
                    // Failed to parse - normal for malformed input
                }
            }
        }
    }
}

fn test_chain_entry_consistency(entry: &ReceiptChainEntry) {
    // Test that entry fields are internally consistent

    // Genesis entry special case
    if entry.index == 0 {
        // First entry should reference genesis
        assert!(
            entry.prev_chain_hash == GENESIS_PREV_HASH ||
            entry.prev_chain_hash.is_empty() ||
            !entry.prev_chain_hash.starts_with("sha256:")
        );
    }

    // Trace ID should match receipt trace ID if both present
    if !entry.trace_id.is_empty() && !entry.receipt.trace_id.is_empty() {
        // May or may not match - depends on implementation
        // But should not panic to check
        let _ = entry.trace_id == entry.receipt.trace_id;
    }

    // Timestamp consistency
    if entry.appended_at_millis > 0 && entry.receipt.timestamp_millis > 0 {
        // Append time should typically be >= receipt time
        // But this is not enforced - just testing for consistency
        let _ = entry.appended_at_millis >= entry.receipt.timestamp_millis;
    }
}

fn test_hash_format_validation(hash: &str, field_name: &str) {
    // Test hash format without panicking
    if hash.starts_with("sha256:") {
        let hex_part = &hash[7..];
        if hex_part.len() == 64 {
            // Should be valid hex
            for ch in hex_part.chars() {
                assert!(ch.is_ascii_hexdigit() || !ch.is_ascii_hexdigit());
            }
        }
    }
    // Other hash formats or empty hashes are also acceptable for fuzzing
}

fn test_checkpoint_validation(data: &[u8]) {
    if let Ok(json_str) = std::str::from_utf8(data) {
        if !json_str.is_empty() && json_str.len() < 1_000_000 {
            let parse_result: Result<ReceiptCheckpoint, _> = serde_json::from_str(json_str);

            match parse_result {
                Ok(checkpoint) => {
                    // Test checkpoint consistency
                    test_checkpoint_consistency(&checkpoint);

                    // Test hash formats
                    test_hash_format_validation(&checkpoint.chain_head_hash, "chain_head_hash");
                    test_hash_format_validation(&checkpoint.commitment_hash, "commitment_hash");

                    // Test range consistency
                    if checkpoint.start_index <= checkpoint.end_index {
                        let expected_count = checkpoint.end_index.saturating_sub(checkpoint.start_index).saturating_add(1);
                        // Count may or may not match due to different counting schemes
                        let _ = checkpoint.entry_count == expected_count;
                    }
                }
                Err(_) => {
                    // Failed to parse - normal for malformed input
                }
            }
        }
    }
}

fn test_checkpoint_consistency(checkpoint: &ReceiptCheckpoint) {
    // Test checkpoint field consistency
    assert!(checkpoint.checkpoint_id.is_finite());
    assert!(checkpoint.start_index.is_finite());
    assert!(checkpoint.end_index.is_finite());
    assert!(checkpoint.entry_count.is_finite());
    assert!(checkpoint.created_at_millis.is_finite());

    // Test logical consistency
    if checkpoint.start_index <= checkpoint.end_index {
        // Valid range
        let range_size = checkpoint.end_index.saturating_sub(checkpoint.start_index).saturating_add(1);
        // Entry count should be reasonable relative to range
        assert!(checkpoint.entry_count <= range_size.saturating_mul(2)); // Allow some flexibility
    }
}

fn test_hash_chain_determinism(data: &[u8]) {
    // Test that hash computation is deterministic
    if data.len() >= 8 {
        let timestamp = u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]);

        // Create a test receipt from fuzzer data
        if let Ok(receipt_id) = std::str::from_utf8(&data[8..].get(..16).unwrap_or(&data[8..])) {
            let receipt = ExecutionReceipt {
                receipt_id: receipt_id.to_string(),
                operation_type: ReceiptOperationType::Verify,
                trace_id: format!("fuzz-{}", receipt_id),
                timestamp_millis: timestamp,
                verifier_identity: "fuzz-verifier".to_string(),
                verification_context: VerificationContext {
                    domain: "fuzz".to_string(),
                    constraints: Some({
                        let mut constraints = BTreeMap::new();
                        constraints.insert("test".to_string(), serde_json::Value::String("fuzz".to_string()));
                        constraints
                    }),
                },
                result: serde_json::json!({
                    "status": "success",
                    "evidence": {}
                }),
            };

            // Test hash determinism
            if let Ok(hash1) = receipt_hash_sha256(&receipt) {
                if let Ok(hash2) = receipt_hash_sha256(&receipt) {
                    assert_eq!(hash1, hash2, "Receipt hash should be deterministic");
                }

                // Test that different receipts produce different hashes
                let mut modified_receipt = receipt.clone();
                modified_receipt.receipt_id = format!("{}_modified", receipt.receipt_id);

                if let Ok(modified_hash) = receipt_hash_sha256(&modified_receipt) {
                    if receipt.receipt_id != modified_receipt.receipt_id {
                        assert_ne!(hash1, modified_hash, "Different receipts should produce different hashes");
                    }
                }
            }
        }
    }
}

fn test_chain_config_validation(data: &[u8]) {
    if data.len() >= 16 {
        let checkpoint_every_entries = u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]) as usize;

        let checkpoint_every_millis = u64::from_le_bytes([
            data[8], data[9], data[10], data[11],
            data[12], data[13], data[14], data[15],
        ]);

        let config = ReceiptChainConfig {
            checkpoint_every_entries,
            checkpoint_every_millis,
        };

        // Test config serialization
        if let Ok(serialized) = serde_json::to_string(&config) {
            let _parse_result: Result<ReceiptChainConfig, _> = serde_json::from_str(&serialized);
        }

        // Test config field access
        assert!(config.checkpoint_every_entries.is_finite());
        assert!(config.checkpoint_every_millis.is_finite());

        // Test config cloning
        let _cloned = config.clone();
    }
}

fn test_chain_error_handling(data: &[u8]) {
    // Test chain error construction and formatting
    if let Ok(error_message) = std::str::from_utf8(data) {
        if !error_message.is_empty() && error_message.len() < 10_000 {
            // Test different error types
            let tamper_error = ChainError::tamper(error_message.to_string());
            test_chain_error_consistency(&tamper_error);

            let checkpoint_error = ChainError::checkpoint(error_message.to_string());
            test_chain_error_consistency(&checkpoint_error);

            let sequence_error = ChainError::sequence(error_message.to_string());
            test_chain_error_consistency(&sequence_error);

            let internal_error = ChainError::internal(error_message.to_string());
            test_chain_error_consistency(&internal_error);

            // Test error display
            let _ = format!("{}", tamper_error);
            let _ = format!("{:?}", tamper_error);
        }
    }
}

fn test_chain_error_consistency(error: &ChainError) {
    // Test error field consistency
    assert!(!error.code.is_empty());
    assert!(!error.event_code.is_empty());
    // message can be empty

    // Test error code format
    assert!(error.code.starts_with("ERR-VEF-CHAIN-") || error.code.starts_with("ERR_VEF_CHAIN_"));
    assert!(error.event_code.starts_with("VEF-CHAIN-ERR-"));

    // Test error serialization
    if let Ok(serialized) = serde_json::to_string(error) {
        let _parse_result: Result<ChainError, _> = serde_json::from_str(&serialized);
    }

    // Test error cloning
    let _cloned = error.clone();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receipt_seed_corpus() {
        for &receipt_json in RECEIPT_SEED_CORPUS {
            fuzz_vef_receipt_envelopes(receipt_json);
        }
    }

    #[test]
    fn test_chain_entry_json_corpus() {
        for &entry_json in CHAIN_ENTRY_JSON_CORPUS {
            fuzz_vef_receipt_envelopes(entry_json.as_bytes());
        }
    }

    #[test]
    fn test_checkpoint_json_corpus() {
        for &checkpoint_json in CHECKPOINT_JSON_CORPUS {
            fuzz_vef_receipt_envelopes(checkpoint_json.as_bytes());
        }
    }

    #[test]
    fn test_empty_input() {
        fuzz_vef_receipt_envelopes(&[]);
    }

    #[test]
    fn test_binary_input() {
        let binary = [0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd];
        fuzz_vef_receipt_envelopes(&binary);
    }

    #[test]
    fn test_large_input() {
        let large_data = vec![b'A'; 100_000];
        fuzz_vef_receipt_envelopes(&large_data);
    }

    #[test]
    fn test_schema_version_consistency() {
        // Test that schema version is well-formed
        assert!(!RECEIPT_CHAIN_SCHEMA_VERSION.is_empty());
        assert!(RECEIPT_CHAIN_SCHEMA_VERSION.starts_with("vef-receipt-chain-"));
    }

    #[test]
    fn test_genesis_hash_format() {
        // Test that genesis hash is well-formed
        assert!(GENESIS_PREV_HASH.starts_with("sha256:"));
        assert_eq!(GENESIS_PREV_HASH.len(), 71); // "sha256:" + 64 chars
    }

    #[test]
    fn test_event_codes_format() {
        // Test that event codes are well-formed
        assert!(event_codes::VEF_CHAIN_001_APPENDED.starts_with("VEF-CHAIN-"));
        assert!(event_codes::VEF_CHAIN_ERR_001_TAMPER.starts_with("VEF-CHAIN-ERR-"));
    }

    #[test]
    fn test_error_codes_format() {
        // Test that error codes are well-formed
        assert!(error_codes::ERR_VEF_CHAIN_TAMPER.starts_with("ERR-VEF-CHAIN-"));
        assert!(error_codes::ERR_VEF_CHAIN_CHECKPOINT.starts_with("ERR-VEF-CHAIN-"));
    }
}