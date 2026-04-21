//! Golden artifact tests for lane scheduler telemetry snapshots
//!
//! Tests deterministic output format stability for:
//! - LaneTelemetrySnapshot serialization across policy variations
//! - Schedule plan outputs under different epoch conditions
//! - Audit log entries with scrubbed dynamic values
//! - Policy validation error messages
//!
//! Complements runtime_lane_scheduler_conformance.rs by focusing on output format
//! validation rather than behavioral correctness testing.

use frankenengine_node::runtime::lane_scheduler::{
    LaneConfig, LaneMappingPolicy, LaneScheduler, LaneSchedulerError, LaneTelemetrySnapshot,
    SchedulerLane, TaskClass, task_classes,
};
use regex::Regex;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// Standard scrubber for lane scheduler outputs
pub struct LaneSchedulerScrubber {
    rules: Vec<(Regex, &'static str)>,
}

impl LaneSchedulerScrubber {
    pub fn new() -> Self {
        Self {
            rules: vec![
                // Timestamps → [TIMESTAMP]
                (Regex::new(r"\d{13,}").unwrap(), "[TIMESTAMP]"),
                // Nonces and random IDs → [NONCE]
                (Regex::new(r"nonce[\":]?\s*[\"']?[a-f0-9]{16,}[\"']?").unwrap(), "nonce: \"[NONCE]\""),
                // Task IDs → [TASK_ID]
                (Regex::new(r"(task_id|trace_id)[\":]?\s*[\"']?[a-zA-Z0-9_-]{8,}[\"']?").unwrap(), "$1: \"[TASK_ID]\""),
                // Memory addresses → [ADDR]
                (Regex::new(r"0x[0-9a-f]{6,16}").unwrap(), "[ADDR]"),
                // Random session IDs → [SESSION_ID]
                (Regex::new(r"session_id[\":]?\s*[\"']?[a-f0-9-]{20,}[\"']?").unwrap(), "session_id: \"[SESSION_ID]\""),
                // Durations with high precision → [DURATION]
                (Regex::new(r"\d+\.\d{6,}\s*(ms|us|ns)").unwrap(), "[DURATION]"),
                // Thread IDs → [THREAD_ID]
                (Regex::new(r"thread_id[\":]?\s*\d+").unwrap(), "thread_id: \"[THREAD_ID]\""),
            ],
        }
    }

    pub fn scrub(&self, input: &str) -> String {
        let mut result = input.to_string();
        for (regex, replacement) in &self.rules {
            result = regex.replace_all(&result, *replacement).to_string();
        }
        result
    }
}

/// Get path to golden file for test
fn golden_path(test_name: &str) -> PathBuf {
    PathBuf::from("tests/golden/lane_scheduler").join(format!("{}.golden", test_name))
}

/// The core golden comparison function for lane scheduler tests
fn assert_lane_scheduler_golden(test_name: &str, actual: &str) {
    let scrubber = LaneSchedulerScrubber::new();
    let scrubbed = scrubber.scrub(actual);

    let golden_path = golden_path(test_name);

    // UPDATE MODE: overwrite golden with actual output
    if std::env::var("UPDATE_GOLDENS").is_ok() {
        fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
        fs::write(&golden_path, &scrubbed).unwrap();
        eprintln!("[GOLDEN] Updated: {}", golden_path.display());
        return;
    }

    // COMPARE MODE: diff actual vs golden
    let expected = fs::read_to_string(&golden_path)
        .unwrap_or_else(|_| panic!(
            "Golden file missing: {}\n\
             Run with UPDATE_GOLDENS=1 to create it\n\
             Then review and commit: git diff tests/golden/lane_scheduler/",
            golden_path.display()
        ));

    if scrubbed != expected {
        // Write actual for easy diffing
        let actual_path = golden_path.with_extension("actual");
        fs::write(&actual_path, &scrubbed).unwrap();

        panic!(
            "GOLDEN MISMATCH: {test_name}\n\n\
             To update: UPDATE_GOLDENS=1 cargo test -- {test_name}\n\
             To review: diff {} {}",
            golden_path.display(),
            actual_path.display(),
        );
    }
}

/// Assert golden for JSON with automatic pretty-printing and scrubbing
fn assert_lane_scheduler_json_golden(test_name: &str, value: &Value) {
    let actual = serde_json::to_string_pretty(value).unwrap();
    assert_lane_scheduler_golden(test_name, &actual);
}

/// Helper to create a minimal policy for deterministic testing
fn minimal_policy() -> LaneMappingPolicy {
    let mut policy = LaneMappingPolicy::new();
    policy
        .add_lane(LaneConfig::new(SchedulerLane::Background, 10, 2))
        .expect("minimal policy creation should succeed");
    policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
    policy
}

/// Helper to create a multi-lane policy for complex scheduling scenarios
fn multi_lane_policy() -> LaneMappingPolicy {
    let mut policy = LaneMappingPolicy::new();

    // Control critical lane - high priority, low concurrency
    policy.add_lane(LaneConfig::new(SchedulerLane::ControlCritical, 100, 1)).unwrap();
    policy.add_rule(&task_classes::epoch_transition(), SchedulerLane::ControlCritical);

    // Remote effect lane - medium priority, medium concurrency
    policy.add_lane(LaneConfig::new(SchedulerLane::RemoteEffect, 50, 4)).unwrap();
    policy.add_rule(&task_classes::remote_computation(), SchedulerLane::RemoteEffect);

    // Background lane - low priority, high concurrency
    policy.add_lane(LaneConfig::new(SchedulerLane::Background, 10, 8)).unwrap();
    policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
    policy.add_rule(&task_classes::garbage_collection(), SchedulerLane::Background);

    policy
}

#[test]
fn golden_telemetry_snapshot_minimal_scheduler() {
    let mut scheduler = LaneScheduler::new(minimal_policy()).unwrap();

    // Admit a single task for deterministic state
    let _assignment = scheduler
        .assign_task(&task_classes::log_rotation(), 1000000, "golden-test-1")
        .unwrap();

    // Mark task as completed for deterministic telemetry
    scheduler.mark_task_completed("golden-test-1", 1000100).unwrap();

    let snapshot = scheduler.telemetry_snapshot(1000200);
    let json_value = serde_json::to_value(&snapshot).unwrap();

    assert_lane_scheduler_json_golden("minimal_scheduler_snapshot", &json_value);
}

#[test]
fn golden_telemetry_snapshot_multi_lane_scheduler() {
    let mut scheduler = LaneScheduler::new(multi_lane_policy()).unwrap();

    // Admit tasks across different lanes for comprehensive telemetry
    let _assignment1 = scheduler
        .assign_task(&task_classes::epoch_transition(), 2000000, "epoch-task-1")
        .unwrap();

    let _assignment2 = scheduler
        .assign_task(&task_classes::remote_computation(), 2000100, "remote-task-1")
        .unwrap();

    let _assignment3 = scheduler
        .assign_task(&task_classes::log_rotation(), 2000200, "log-task-1")
        .unwrap();

    // Complete some tasks to show different lane states
    scheduler.mark_task_completed("epoch-task-1", 2000300).unwrap();
    scheduler.mark_task_completed("log-task-1", 2000400).unwrap();

    let snapshot = scheduler.telemetry_snapshot(2000500);
    let json_value = serde_json::to_value(&snapshot).unwrap();

    assert_lane_scheduler_json_golden("multi_lane_scheduler_snapshot", &json_value);
}

#[test]
fn golden_telemetry_snapshot_capacity_enforcement() {
    // Create policy with capacity of 1 to test cap enforcement
    let mut policy = LaneMappingPolicy::new();
    policy.add_lane(LaneConfig::new(SchedulerLane::RemoteEffect, 50, 1)).unwrap();
    policy.add_rule(&task_classes::remote_computation(), SchedulerLane::RemoteEffect);

    let mut scheduler = LaneScheduler::new(policy).unwrap();

    // First admission should succeed
    let _assignment1 = scheduler
        .assign_task(&task_classes::remote_computation(), 3000000, "cap-test-1")
        .unwrap();

    // Second admission should fail due to capacity
    let assignment2_result = scheduler
        .assign_task(&task_classes::remote_computation(), 3000100, "cap-test-2");

    let snapshot = scheduler.telemetry_snapshot(3000200);
    let json_value = serde_json::to_value(&snapshot).unwrap();

    // Verify assignment failure was due to capacity
    assert!(assignment2_result.is_err());
    assert!(matches!(assignment2_result.unwrap_err(), LaneSchedulerError::CapExceeded { .. }));

    assert_lane_scheduler_json_golden("capacity_enforcement_snapshot", &json_value);
}

#[test]
fn golden_telemetry_snapshot_epoch_boundary_conditions() {
    let mut scheduler = LaneScheduler::new(minimal_policy()).unwrap();

    // Test with epoch boundary timestamp values
    let epoch_start = 4000000000u64; // Large epoch value
    let epoch_end = epoch_start + 1000;

    let _assignment = scheduler
        .assign_task(&task_classes::log_rotation(), epoch_start, "epoch-boundary-task")
        .unwrap();

    scheduler.mark_task_completed("epoch-boundary-task", epoch_end).unwrap();

    let snapshot = scheduler.telemetry_snapshot(epoch_end + 100);
    let json_value = serde_json::to_value(&snapshot).unwrap();

    assert_lane_scheduler_json_golden("epoch_boundary_snapshot", &json_value);
}

#[test]
fn golden_scheduler_policy_serialization() {
    let policy = multi_lane_policy();
    let json_value = serde_json::to_value(&policy).unwrap();

    assert_lane_scheduler_json_golden("multi_lane_policy_config", &json_value);
}

#[test]
fn golden_scheduler_policy_validation_errors() {
    // Test various invalid policy configurations
    let mut invalid_policies = Vec::new();

    // Empty policy
    let empty_policy = LaneMappingPolicy::new();
    invalid_policies.push(("empty_policy", empty_policy.validate()));

    // Policy with lane but no rules
    let mut no_rules_policy = LaneMappingPolicy::new();
    no_rules_policy.add_lane(LaneConfig::new(SchedulerLane::Background, 10, 2)).unwrap();
    invalid_policies.push(("no_rules_policy", no_rules_policy.validate()));

    // Policy with zero priority weight
    let mut zero_priority_policy = LaneMappingPolicy::new();
    let mut config = LaneConfig::new(SchedulerLane::Background, 10, 2);
    config.priority_weight = 0;
    let _ = zero_priority_policy.add_lane(config);
    invalid_policies.push(("zero_priority_policy", zero_priority_policy.validate()));

    // Collect all validation results
    let mut validation_results = Vec::new();
    for (name, result) in invalid_policies {
        validation_results.push(serde_json::json!({
            "policy_type": name,
            "validation_result": result.map(|_| "valid").unwrap_or_else(|e| e.as_str()),
            "is_valid": result.is_ok()
        }));
    }

    let json_value = serde_json::json!({
        "validation_results": validation_results
    });

    assert_lane_scheduler_json_golden("policy_validation_errors", &json_value);
}

#[test]
fn golden_scheduler_audit_log_entries() {
    let mut scheduler = LaneScheduler::new(multi_lane_policy()).unwrap();

    // Create a sequence of operations that generates audit log entries
    let base_timestamp = 5000000u64;

    // Admit tasks
    let _assignment1 = scheduler
        .assign_task(&task_classes::epoch_transition(), base_timestamp, "audit-epoch-1")
        .unwrap();

    let _assignment2 = scheduler
        .assign_task(&task_classes::remote_computation(), base_timestamp + 100, "audit-remote-1")
        .unwrap();

    // Try to admit task that will fail (to different lane than configured)
    let unknown_task = TaskClass::new("unknown_task_class");
    let _failed_assignment = scheduler
        .assign_task(&unknown_task, base_timestamp + 200, "audit-fail-1");

    // Complete tasks
    scheduler.mark_task_completed("audit-epoch-1", base_timestamp + 300).unwrap();
    scheduler.mark_task_completed("audit-remote-1", base_timestamp + 400).unwrap();

    let snapshot = scheduler.telemetry_snapshot(base_timestamp + 500);

    // Extract audit log for golden testing
    let audit_entries = serde_json::json!({
        "audit_log_count": snapshot.audit_log.len(),
        "schema_version": snapshot.schema_version,
        "snapshot_timestamp": "[SCRUBBED_TIMESTAMP]",
        "lane_states": snapshot.counters.len(),
    });

    assert_lane_scheduler_json_golden("scheduler_audit_log_entries", &audit_entries);
}

#[test]
fn golden_scheduler_starvation_detection_output() {
    // Create policy with starvation window for testing
    let mut policy = LaneMappingPolicy::new();
    let mut config = LaneConfig::new(SchedulerLane::Background, 1, 4); // Low priority
    config.starvation_window_ms = 1000; // 1 second window
    policy.add_lane(config).unwrap();
    policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);

    let mut scheduler = LaneScheduler::new(policy).unwrap();

    let base_timestamp = 6000000u64;

    // Admit task but don't complete it (simulating starvation)
    let _assignment = scheduler
        .assign_task(&task_classes::log_rotation(), base_timestamp, "starve-test-1")
        .unwrap();

    // Take snapshot after starvation window should trigger
    let snapshot = scheduler.telemetry_snapshot(base_timestamp + 2000); // 2 seconds later
    let json_value = serde_json::to_value(&snapshot).unwrap();

    assert_lane_scheduler_json_golden("starvation_detection_snapshot", &json_value);
}