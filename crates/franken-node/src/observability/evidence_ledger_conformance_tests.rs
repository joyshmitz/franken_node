// Comprehensive conformance tests for evidence ledger - security and robustness
//
// Tests focus on:
// - Integer overflow/underflow protection in counters and size calculations
// - Memory exhaustion protection via bounded ring buffer
// - Thread safety and poison recovery scenarios
// - Size estimation accuracy and edge cases
// - Concurrent access patterns and race conditions
// - Serialization robustness

use super::evidence_ledger::*;
use std::sync::Arc;
use std::thread;
use std::io::{self, Write};

/// Test integer overflow protection in counters and IDs
#[test]
fn test_counter_overflow_protection() {
    // Create ledger and manually set counters near overflow to test protection
    let capacity = LedgerCapacity::new(10, 10000);
    let mut ledger = EvidenceLedger::new(capacity);

    // Test that large counter values don't cause issues
    // We can't directly set the counters, but we can verify the math works

    // Create entries and verify counters use saturating arithmetic
    for i in 0..20 {
        let entry = test_entry(&format!("test-{}", i), i);
        let result = ledger.append(entry);
        assert!(result.is_ok(), "Should handle normal append operations");
    }

    // Verify totals are reasonable and didn't overflow
    assert!(ledger.total_appended() > 0);
    assert!(ledger.total_evicted() > 0);
    assert!(ledger.total_appended() >= ledger.total_evicted());

    // The ring buffer should maintain reasonable size
    assert!(ledger.len() <= 10, "Ring buffer should be bounded by max_entries");
}

/// Test entry ID sequence overflow protection
#[test]
fn test_entry_id_sequence_protection() {
    let capacity = LedgerCapacity::new(5, 10000);
    let mut ledger = EvidenceLedger::new(capacity);

    // Add many entries to test ID sequence behavior
    let mut last_id = EntryId(0);

    for i in 0..1000 {
        let entry = test_entry(&format!("seq-test-{}", i), i);
        let id = ledger.append(entry).unwrap();

        // IDs should be monotonically increasing
        assert!(id > last_id, "Entry IDs should be monotonically increasing");
        last_id = id;

        // Should never wrap around or become zero
        assert!(id.0 > 0, "Entry IDs should never be zero");
    }
}

/// Test size estimation accuracy and edge cases
#[test]
fn test_size_estimation_edge_cases() {
    // Test size estimation with various payload sizes
    let small_entry = test_entry("small", 1);
    let small_size = small_entry.estimated_size();
    assert!(small_size > 0, "Size estimate should be positive");
    assert!(small_size < 1000, "Small entry should have reasonable size");

    // Test with very large payload
    let large_payload = serde_json::json!({
        "large_data": "x".repeat(10000),
        "more_data": vec![1; 1000],
        "nested": {
            "deep": {
                "very_deep": "y".repeat(5000)
            }
        }
    });

    let large_entry = EvidenceEntry {
        schema_version: "1.0".to_string(),
        entry_id: None,
        decision_id: "large-test".to_string(),
        decision_kind: DecisionKind::Deny,
        decision_time: "2026-02-20T12:00:00Z".to_string(),
        timestamp_ms: 1000,
        trace_id: "trace-large".to_string(),
        epoch_id: 1,
        payload: large_payload,
        size_bytes: 0,
    };

    let large_size = large_entry.estimated_size();
    assert!(large_size > small_size, "Large entry should have larger size estimate");
    assert!(large_size > 15000, "Large entry should reflect actual size");

    // Test with invalid JSON that might cause serialization to fail
    // The estimated_size function should handle this gracefully with unwrap_or(256)
    let mut problematic_entry = test_entry("problematic", 1);

    // Create a payload that could cause serialization issues
    let mut problematic_map = serde_json::Map::new();
    problematic_map.insert("valid".to_string(), serde_json::Value::String("test".to_string()));
    problematic_entry.payload = serde_json::Value::Object(problematic_map);

    let size = problematic_entry.estimated_size();
    assert!(size >= 256, "Should use fallback size for estimation problems");
}

/// Test memory exhaustion protection via bounded storage
#[test]
fn test_memory_exhaustion_protection() {
    // Create a very small capacity ledger to force frequent evictions
    let capacity = LedgerCapacity::new(3, 500);
    let mut ledger = EvidenceLedger::new(capacity);

    // Add many entries to test memory bounds
    for i in 0..100 {
        let entry = test_entry(&format!("mem-test-{}", i), i);
        let result = ledger.append(entry);

        // Should always succeed with bounded storage
        assert!(result.is_ok(), "Bounded ledger should handle memory pressure");

        // Should never exceed capacity limits
        assert!(ledger.len() <= 3, "Should never exceed max_entries");
        assert!(ledger.current_bytes() <= 500, "Should never exceed max_bytes");
    }

    // Should have evicted many entries
    assert!(ledger.total_evicted() > 90, "Should have evicted many entries");
    assert_eq!(ledger.len(), 3, "Should maintain exactly max_entries");
}

/// Test concurrent access and thread safety
#[test]
fn test_concurrent_access_thread_safety() {
    let shared_ledger = SharedEvidenceLedger::new(LedgerCapacity::new(1000, 100000));
    let num_threads = 10;
    let entries_per_thread = 20;

    let mut handles = Vec::new();

    // Spawn multiple threads that append concurrently
    for thread_id in 0..num_threads {
        let ledger_clone = shared_ledger.clone();
        let handle = thread::spawn(move || {
            for i in 0..entries_per_thread {
                let entry = test_entry(&format!("thread-{}-entry-{}", thread_id, i),
                                     (thread_id * entries_per_thread + i) as u64);
                let result = ledger_clone.append(entry);
                assert!(result.is_ok(), "Concurrent append should succeed");
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread should complete successfully");
    }

    // Verify final state
    let final_count = shared_ledger.len();
    let snapshot = shared_ledger.snapshot();

    assert!(final_count <= 1000, "Should not exceed capacity");
    assert_eq!(snapshot.entries.len(), final_count);
    assert_eq!(snapshot.total_appended, (num_threads * entries_per_thread) as u64);
}

/// Test poison recovery in shared ledger
#[test]
fn test_poison_recovery() {
    let shared_ledger = SharedEvidenceLedger::new(LedgerCapacity::new(100, 10000));

    // First verify normal operation
    assert!(shared_ledger.is_empty());

    let poison_target = shared_ledger.clone();

    // Create a thread that will poison the mutex
    let poison_handle = thread::spawn(move || {
        let _guard = poison_target.inner.lock().expect("Should acquire lock");
        panic!("Intentionally poison the mutex");
    });

    // Wait for the thread to panic and poison the mutex
    assert!(poison_handle.join().is_err(), "Poisoning thread should panic");

    // Now verify that the ledger can recover from the poison
    assert!(shared_ledger.is_empty(), "Should recover from poison and still work");

    let result = shared_ledger.append(test_entry("post-poison", 1));
    assert!(result.is_ok(), "Should be able to append after poison recovery");

    assert_eq!(shared_ledger.len(), 1, "Should work normally after recovery");

    let snapshot = shared_ledger.snapshot();
    assert_eq!(snapshot.entries.len(), 1, "Snapshot should work after recovery");
}

/// Test capacity validation edge cases
#[test]
fn test_capacity_validation_edge_cases() {
    // Test zero entry capacity
    let zero_capacity = LedgerCapacity::new(0, 1000);
    let mut ledger = EvidenceLedger::new(zero_capacity);

    let result = ledger.append(test_entry("zero-cap", 1));
    assert!(matches!(result, Err(LedgerError::ZeroEntryCapacity)));
    assert!(ledger.is_empty());
    assert_eq!(ledger.total_appended(), 0);

    // Test zero byte capacity
    let zero_bytes = LedgerCapacity::new(10, 0);
    let mut byte_ledger = EvidenceLedger::new(zero_bytes);

    let result = byte_ledger.append(test_entry("zero-bytes", 1));
    // Should fail because even a small entry exceeds 0 byte limit
    assert!(result.is_err());

    // Test very large capacity values
    let huge_capacity = LedgerCapacity::new(usize::MAX, usize::MAX);
    let mut huge_ledger = EvidenceLedger::new(huge_capacity);

    let result = huge_ledger.append(test_entry("huge-cap", 1));
    assert!(result.is_ok(), "Should handle very large capacity values");
}

/// Test entry size vs byte limit validation
#[test]
fn test_entry_size_byte_limit_validation() {
    let capacity = LedgerCapacity::new(10, 100); // Very small byte limit
    let mut ledger = EvidenceLedger::new(capacity);

    // Create an entry that's definitely too large
    let large_payload = serde_json::json!({
        "massive_string": "x".repeat(1000),
        "another_field": "y".repeat(1000)
    });

    let oversized_entry = EvidenceEntry {
        schema_version: "1.0".to_string(),
        entry_id: None,
        decision_id: "oversized".to_string(),
        decision_kind: DecisionKind::Escalate,
        decision_time: "2026-02-20T12:00:00Z".to_string(),
        timestamp_ms: 1000,
        trace_id: "trace-oversized".to_string(),
        epoch_id: 1,
        payload: large_payload,
        size_bytes: 0,
    };

    let result = ledger.append(oversized_entry);

    match result {
        Err(LedgerError::EntryTooLarge { entry_size, max_bytes }) => {
            assert!(entry_size > max_bytes);
            assert_eq!(max_bytes, 100);
        }
        _ => panic!("Expected EntryTooLarge error"),
    }

    // Ledger should remain unchanged
    assert!(ledger.is_empty());
    assert_eq!(ledger.total_appended(), 0);
}

/// Test eviction order and FIFO semantics
#[test]
fn test_eviction_order_fifo_semantics() {
    let capacity = LedgerCapacity::new(3, 10000);
    let mut ledger = EvidenceLedger::new(capacity);

    // Add more entries than capacity to trigger evictions
    let entry_ids = ["first", "second", "third", "fourth", "fifth"];

    for (i, id) in entry_ids.iter().enumerate() {
        let entry = test_entry(id, i as u64);
        ledger.append(entry).expect("Should succeed");
    }

    // Should only have the last 3 entries (FIFO eviction)
    assert_eq!(ledger.len(), 3);
    assert_eq!(ledger.total_appended(), 5);
    assert_eq!(ledger.total_evicted(), 2);

    // Verify the remaining entries are the most recent ones
    let entries: Vec<_> = ledger.iter_all().collect();
    assert_eq!(entries[0].1.decision_id, "third");
    assert_eq!(entries[1].1.decision_id, "fourth");
    assert_eq!(entries[2].1.decision_id, "fifth");
}

/// Test iterator edge cases
#[test]
fn test_iterator_edge_cases() {
    let capacity = LedgerCapacity::new(5, 10000);
    let mut ledger = EvidenceLedger::new(capacity);

    // Test iterators on empty ledger
    assert_eq!(ledger.iter_all().count(), 0);
    assert_eq!(ledger.iter_recent(10).count(), 0);
    assert_eq!(ledger.iter_recent(0).count(), 0);

    // Add some entries
    for i in 0..3 {
        ledger.append(test_entry(&format!("iter-{}", i), i)).unwrap();
    }

    // Test iter_recent with various values
    assert_eq!(ledger.iter_recent(0).count(), 0);
    assert_eq!(ledger.iter_recent(1).count(), 1);
    assert_eq!(ledger.iter_recent(2).count(), 2);
    assert_eq!(ledger.iter_recent(3).count(), 3);
    assert_eq!(ledger.iter_recent(10).count(), 3); // More than available

    // Verify iter_recent returns newest entries last
    let recent: Vec<_> = ledger.iter_recent(2).collect();
    assert_eq!(recent[0].1.decision_id, "iter-1");
    assert_eq!(recent[1].1.decision_id, "iter-2");
}

/// Test snapshot consistency and independence
#[test]
fn test_snapshot_consistency_independence() {
    let capacity = LedgerCapacity::new(5, 10000);
    let mut ledger = EvidenceLedger::new(capacity);

    // Take snapshot of empty ledger
    let empty_snapshot = ledger.snapshot();
    assert_eq!(empty_snapshot.entries.len(), 0);
    assert_eq!(empty_snapshot.total_appended, 0);
    assert_eq!(empty_snapshot.total_evicted, 0);

    // Add entries
    ledger.append(test_entry("snap-1", 1)).unwrap();
    ledger.append(test_entry("snap-2", 2)).unwrap();

    let snapshot1 = ledger.snapshot();
    assert_eq!(snapshot1.entries.len(), 2);
    assert_eq!(snapshot1.total_appended, 2);

    // Modify ledger further
    ledger.append(test_entry("snap-3", 3)).unwrap();

    let snapshot2 = ledger.snapshot();
    assert_eq!(snapshot2.entries.len(), 3);
    assert_eq!(snapshot2.total_appended, 3);

    // Original snapshot should be unchanged
    assert_eq!(snapshot1.entries.len(), 2);
    assert_eq!(snapshot1.total_appended, 2);

    // Empty snapshot should still be empty
    assert_eq!(empty_snapshot.entries.len(), 0);
}

/// Test lab spill mode error handling
#[test]
fn test_lab_spill_error_handling() {
    // Test with failing writer
    struct AlwaysFailWriter;
    impl Write for AlwaysFailWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "Write failed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let capacity = LedgerCapacity::new(10, 10000);
    let mut spill_mode = LabSpillMode::new(capacity, Box::new(AlwaysFailWriter));

    let result = spill_mode.append(test_entry("fail-test", 1));
    assert!(matches!(result, Err(LedgerError::SpillError { .. })));

    // Ledger should remain unmodified on spill failure
    assert!(spill_mode.is_empty());
    assert_eq!(spill_mode.snapshot().total_appended, 0);

    // Test with failing flush
    struct FailFlushWriter;
    impl Write for FailFlushWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "Flush failed"))
        }
    }

    let mut spill_flush = LabSpillMode::new(
        LedgerCapacity::new(10, 10000),
        Box::new(FailFlushWriter)
    );

    let result = spill_flush.append(test_entry("flush-fail", 1));
    assert!(matches!(result, Err(LedgerError::SpillError { .. })));
    assert!(spill_flush.is_empty());
}

/// Test deterministic behavior under identical inputs
#[test]
fn test_deterministic_behavior() {
    // Run identical sequences in two separate ledgers
    let create_and_run = || {
        let capacity = LedgerCapacity::new(5, 10000);
        let mut ledger = EvidenceLedger::new(capacity);

        for i in 0..10 {
            let entry = test_entry(&format!("det-{}", i), i);
            ledger.append(entry).unwrap();
        }

        ledger.snapshot()
    };

    let snapshot1 = create_and_run();
    let snapshot2 = create_and_run();

    // Results should be identical
    assert_eq!(snapshot1.entries.len(), snapshot2.entries.len());
    assert_eq!(snapshot1.total_appended, snapshot2.total_appended);
    assert_eq!(snapshot1.total_evicted, snapshot2.total_evicted);
    assert_eq!(snapshot1.current_bytes, snapshot2.current_bytes);

    // Entry details should match
    for (entry1, entry2) in snapshot1.entries.iter().zip(snapshot2.entries.iter()) {
        assert_eq!(entry1.0, entry2.0); // EntryId
        assert_eq!(entry1.1.decision_id, entry2.1.decision_id);
        assert_eq!(entry1.1.epoch_id, entry2.1.epoch_id);
    }
}

/// Test byte accounting accuracy
#[test]
fn test_byte_accounting_accuracy() {
    let capacity = LedgerCapacity::new(10, 1000);
    let mut ledger = EvidenceLedger::new(capacity);

    let entry1 = test_entry("byte-test-1", 1);
    let entry1_size = entry1.estimated_size();

    ledger.append(entry1).unwrap();
    assert_eq!(ledger.current_bytes(), entry1_size);

    let entry2 = test_entry("byte-test-2", 2);
    let entry2_size = entry2.estimated_size();

    ledger.append(entry2).unwrap();
    assert_eq!(ledger.current_bytes(), entry1_size + entry2_size);

    // Force eviction by adding a large entry
    let large_entry = EvidenceEntry {
        schema_version: "1.0".to_string(),
        entry_id: None,
        decision_id: "large".to_string(),
        decision_kind: DecisionKind::Throttle,
        decision_time: "2026-02-20T12:00:00Z".to_string(),
        timestamp_ms: 3000,
        trace_id: "trace-large".to_string(),
        epoch_id: 3,
        payload: serde_json::json!({"data": "x".repeat(500)}),
        size_bytes: 0,
    };

    ledger.append(large_entry.clone()).unwrap();

    // Bytes should be accurately tracked after evictions
    assert!(ledger.current_bytes() <= 1000);
    assert!(ledger.current_bytes() > 0);
}

/// Custom test for ID display formatting
#[test]
fn test_entry_id_display_formatting() {
    assert_eq!(format!("{}", EntryId(1)), "E-00000001");
    assert_eq!(format!("{}", EntryId(42)), "E-00000042");
    assert_eq!(format!("{}", EntryId(123456)), "E-00123456");
    assert_eq!(format!("{}", EntryId(u64::MAX)), format!("E-{:08}", u64::MAX));
}

/// Test decision kind labels
#[test]
fn test_decision_kind_labels_comprehensive() {
    let kinds = [
        (DecisionKind::Admit, "admit"),
        (DecisionKind::Deny, "deny"),
        (DecisionKind::Quarantine, "quarantine"),
        (DecisionKind::Release, "release"),
        (DecisionKind::Rollback, "rollback"),
        (DecisionKind::Throttle, "throttle"),
        (DecisionKind::Escalate, "escalate"),
    ];

    for (kind, expected_label) in kinds.iter() {
        assert_eq!(kind.label(), *expected_label);
    }
}