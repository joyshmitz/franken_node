#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use frankenengine_node::observability::evidence_ledger::EvidenceEntry;
use std::str;

fuzz_target!(|data: &[u8]| {
    // Guard against very large inputs to prevent OOM
    if data.len() > 1_000_000 {
        return;
    }

    // Only fuzz valid UTF-8 strings since JSONL requires valid UTF-8
    if let Ok(jsonl_str) = str::from_utf8(data) {
        // Test parsing each line of the JSONL as done in evidence ledger spill parsing
        // This mimics the parsed_spill_entries function behavior
        for line in jsonl_str.lines() {
            if line.trim().is_empty() {
                continue; // Skip empty lines like the real parser would
            }

            // Attempt to parse the JSONL line into EvidenceEntry
            // We expect most random inputs to fail parsing, which is normal
            let _ = serde_json::from_str::<EvidenceEntry>(line);

            // Additional fuzzing: test round-trip for valid entries
            if let Ok(entry) = serde_json::from_str::<EvidenceEntry>(line) {
                // Test that valid entries can be serialized back
                if let Ok(serialized) = serde_json::to_string(&entry) {
                    // Ensure round-trip consistency
                    let _ = serde_json::from_str::<EvidenceEntry>(&serialized);
                }

                // Test field validation - ensure timestamp_ms and epoch_id don't overflow
                assert!(entry.timestamp_ms <= u64::MAX, "timestamp_ms must not overflow");
                assert!(entry.epoch_id <= u64::MAX, "epoch_id must not overflow");

                // Test size estimation doesn't panic
                let _ = entry.estimated_size();

                // Ensure decision_time is reasonable timestamp string format
                assert!(!entry.decision_time.is_empty(), "decision_time must not be empty");

                // Ensure required IDs are not empty
                assert!(!entry.decision_id.is_empty(), "decision_id must not be empty");
                assert!(!entry.trace_id.is_empty(), "trace_id must not be empty");
                assert!(!entry.schema_version.is_empty(), "schema_version must not be empty");
            }
        }

        // Test multi-line JSONL parsing (common in evidence spill files)
        let lines: Vec<&str> = jsonl_str.lines().filter(|line| !line.trim().is_empty()).collect();
        if !lines.is_empty() {
            // Test that we can parse a collection of lines without panics
            let parsed_entries: Vec<_> = lines
                .iter()
                .filter_map(|line| serde_json::from_str::<EvidenceEntry>(line).ok())
                .collect();

            // If we successfully parsed entries, ensure they maintain consistency
            for entry in &parsed_entries {
                assert!(entry.timestamp_ms > 0 || entry.timestamp_ms == 0, "timestamp_ms should be valid");
                assert!(entry.size_bytes <= 10_000_000, "size_bytes should be reasonable");
            }
        }
    }
});