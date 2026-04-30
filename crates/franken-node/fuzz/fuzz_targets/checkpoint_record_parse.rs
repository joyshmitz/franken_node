#![no_main]

use frankenengine_node::runtime::checkpoint::{CheckpointRecord, CheckpointMeta, CheckpointEvent};
use libfuzzer_sys::fuzz_target;
use serde_json;

/// Fuzz harness for checkpoint record deserialization robustness.
///
/// Tests that CheckpointRecord JSON parsing handles malformed input gracefully
/// and maintains structural invariants for valid records.
///
/// Target properties:
/// 1. No panics on arbitrary JSON input
/// 2. Valid records satisfy checkpoint invariants
/// 3. Deserialization errors are well-formed
/// 4. No buffer overflows or memory safety issues
fuzz_target!(|data: &[u8]| {
    // Bound input size to prevent OOM in fuzzer
    if data.len() > 100_000 {  // 100KB limit
        return;
    }

    // Test CheckpointRecord deserialization
    let parse_result = serde_json::from_slice::<CheckpointRecord>(data);
    match parse_result {
        Ok(record) => {
            // STRUCTURAL INVARIANTS for valid checkpoint records

            // 1. IDs should not be empty
            assert!(!record.orchestration_id.trim().is_empty(),
                "Valid checkpoint must have non-empty orchestration_id");

            // 2. Timestamps should be reasonable (not in far future/past)
            let reasonable_min = 1_000_000_000_000u64; // ~2001
            let reasonable_max = 4_000_000_000_000u64; // ~2096
            assert!(record.wall_clock_time >= reasonable_min && record.wall_clock_time <= reasonable_max,
                "Wall clock time should be reasonable: {}", record.wall_clock_time);

            // 3. Iteration count should be finite
            assert!(record.iteration_count < u64::MAX,
                "Iteration count should be bounded");

            // 4. Progress state JSON should be valid
            if !record.progress_state_json.trim().is_empty() {
                let json_parse_result: Result<serde_json::Value, _> =
                    serde_json::from_str(&record.progress_state_json);
                assert!(json_parse_result.is_ok(),
                    "Progress state JSON must be valid if non-empty");
            }

            // 5. Hashes should be reasonable length (not empty, not huge)
            assert!(!record.progress_state_hash.trim().is_empty(),
                "Progress state hash cannot be empty");
            assert!(record.progress_state_hash.len() <= 1024,
                "Progress state hash should be reasonably sized");

            // 6. Test that valid record can be re-serialized
            let reserialize_result = serde_json::to_string(&record);
            assert!(reserialize_result.is_ok(),
                "Valid checkpoint record must be re-serializable");

            // 7. Round-trip property
            if let Ok(reserialized_json) = reserialize_result {
                let reparse_result = serde_json::from_str::<CheckpointRecord>(&reserialized_json);
                match reparse_result {
                    Ok(reparsed) => {
                        assert_eq!(record.checkpoint_id, reparsed.checkpoint_id,
                            "Checkpoint ID must survive round-trip");
                        assert_eq!(record.orchestration_id, reparsed.orchestration_id,
                            "Orchestration ID must survive round-trip");
                        assert_eq!(record.iteration_count, reparsed.iteration_count,
                            "Iteration count must survive round-trip");
                        assert_eq!(record.epoch, reparsed.epoch,
                            "Epoch must survive round-trip");
                        assert_eq!(record.wall_clock_time, reparsed.wall_clock_time,
                            "Wall clock time must survive round-trip");
                    }
                    Err(_) => {
                        panic!("Round-trip failure: parsed record failed to reparse after serialization");
                    }
                }
            }
        }
        Err(_parse_error) => {
            // Invalid input - this is expected for malformed JSON
            // Just verify no panic occurred
        }
    }

    // Test CheckpointMeta deserialization separately
    let meta_parse_result = serde_json::from_slice::<CheckpointMeta>(data);
    if let Ok(meta) = meta_parse_result {
        // CheckpointMeta invariants
        assert!(!meta.orchestration_id.trim().is_empty(),
            "Checkpoint meta must have orchestration ID");
        assert!(meta.wall_clock_time > 0,
            "Meta wall clock time must be positive");

        // Test meta serialization
        let meta_serialize = serde_json::to_string(&meta);
        assert!(meta_serialize.is_ok(),
            "Valid checkpoint meta must serialize");
    }

    // Test CheckpointEvent deserialization
    let event_parse_result = serde_json::from_slice::<CheckpointEvent>(data);
    if let Ok(event) = event_parse_result {
        // Event invariants
        assert!(!event.event_code.trim().is_empty(),
            "Event must have non-empty event code");
        assert!(!event.event_name.trim().is_empty(),
            "Event must have non-empty event name");
        assert!(!event.orchestration_id.trim().is_empty(),
            "Event must have orchestration ID");
        assert!(!event.trace_id.trim().is_empty(),
            "Event must have trace ID");

        // Test event serialization
        let event_serialize = serde_json::to_string(&event);
        assert!(event_serialize.is_ok(),
            "Valid checkpoint event must serialize");
    }

    // Edge case: test empty input
    if data.is_empty() {
        let empty_result = serde_json::from_slice::<CheckpointRecord>(b"");
        assert!(empty_result.is_err(),
            "Empty input should fail to parse as CheckpointRecord");
    }

    // Edge case: test single byte inputs
    if data.len() == 1 {
        let single_byte_result = serde_json::from_slice::<CheckpointRecord>(data);
        // Single bytes should generally fail to parse (except maybe some JSON tokens)
        // Just ensure no panic
        let _ = single_byte_result;
    }
});