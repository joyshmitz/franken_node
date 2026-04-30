#![no_main]

use frankenengine_node::runtime::checkpoint::{CheckpointRecord, CheckpointMeta, CheckpointEvent};
use libfuzzer_sys::fuzz_target;
use serde_json;

/// Real adversarial fuzz harness for checkpoint serialization
///
/// Tests checkpoint deserialization against arbitrary malformed inputs to find:
/// 1. Parse crashes and panics
/// 2. Infinite loops or excessive memory allocation
/// 3. Logic bugs in validation
/// 4. Serialization round-trip failures
fuzz_target!(|data: &[u8]| {
    // Bound input size to prevent OOM and timeouts
    if data.len() > 100_000 {  // 100KB limit
        return;
    }

    // Test CheckpointRecord parsing with adversarial input
    if let Ok(record) = serde_json::from_slice::<CheckpointRecord>(data) {
        // INVARIANT: valid records should round-trip exactly
        if let Ok(reserialized) = serde_json::to_vec(&record) {
            if let Ok(reparsed) = serde_json::from_slice::<CheckpointRecord>(&reserialized) {
                assert_eq!(
                    record, reparsed,
                    "CheckpointRecord round-trip failure"
                );
            }
        }

        // SECURITY: validate bounds on parsed data
        assert!(
            record.orchestration_id.len() <= 256,
            "Orchestration ID too long: {}",
            record.orchestration_id.len()
        );

        assert!(
            record.checkpoint_id.len() <= 128,
            "Checkpoint ID too long: {}",
            record.checkpoint_id.len()
        );

        assert!(
            record.progress_state_json.len() <= 1_000_000,
            "Progress state JSON too long: {}",
            record.progress_state_json.len()
        );

        // LOGIC: validate checkpoint progression invariants
        assert!(
            record.iteration_count < u64::MAX / 2,
            "Iteration count too large: {}",
            record.iteration_count
        );

        // CONTENT: ensure no null bytes in critical fields
        assert!(
            !record.orchestration_id.contains('\0'),
            "Orchestration ID contains null bytes"
        );

        assert!(
            !record.checkpoint_id.contains('\0'),
            "Checkpoint ID contains null bytes"
        );

        // NESTED: test progress state parsing if it looks like JSON
        if record.progress_state_json.starts_with('{') {
            let _: Result<serde_json::Value, _> = serde_json::from_str(&record.progress_state_json);
            // Don't assert - just ensure no crash/panic on nested parsing
        }
    }

    // Test CheckpointMeta parsing
    if let Ok(meta) = serde_json::from_slice::<CheckpointMeta>(data) {
        // Round-trip test
        if let Ok(meta_serialized) = serde_json::to_vec(&meta) {
            if let Ok(meta_reparsed) = serde_json::from_slice::<CheckpointMeta>(&meta_serialized) {
                assert_eq!(meta, meta_reparsed, "CheckpointMeta round-trip failure");
            }
        }

        // Validate meta bounds
        assert!(meta.orchestration_id.len() <= 256);
        assert!(meta.checkpoint_id.len() <= 128);
    }

    // Test CheckpointEvent parsing
    if let Ok(event) = serde_json::from_slice::<CheckpointEvent>(data) {
        // Round-trip test
        if let Ok(event_serialized) = serde_json::to_vec(&event) {
            if let Ok(event_reparsed) = serde_json::from_slice::<CheckpointEvent>(&event_serialized) {
                assert_eq!(event, event_reparsed, "CheckpointEvent round-trip failure");
            }
        }

        // Validate event bounds and content
        assert!(event.orchestration_id.len() <= 256);
        assert!(event.trace_id.len() <= 256);
        assert!(!event.event_code.is_empty(), "Event code cannot be empty");
        assert!(!event.event_name.is_empty(), "Event name cannot be empty");
    }

    // EDGE CASES: test specific problematic patterns

    // Empty input
    if data.is_empty() {
        let empty_results = [
            serde_json::from_slice::<CheckpointRecord>(b""),
            serde_json::from_slice::<CheckpointRecord>(b"{}"),
        ];
        for result in empty_results {
            let _ = result; // Should not crash
        }
    }

    // Very large numbers that could cause overflow
    if data.len() >= 8 {
        let large_num = u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7]
        ]);

        // Test with manufactured large iteration count
        let malicious_json = format!(r#"{{"iteration_count":{},"epoch":1}}"#, large_num);
        let _: Result<serde_json::Value, _> = serde_json::from_str(&malicious_json);
    }

    // Unicode edge cases
    if let Ok(utf8_data) = std::str::from_utf8(data) {
        if utf8_data.contains("orchestration_id") {
            // Try to parse as checkpoint with potential unicode issues
            let _: Result<CheckpointRecord, _> = serde_json::from_str(utf8_data);
        }
    }
});