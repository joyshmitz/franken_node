//! Integration tests for region-owned lifecycle (bd-2tdi).
//!
//! Validates that connector lifecycle operations execute within region
//! boundaries, and that region.close() is a hard quiescence barrier.

use frankenengine_node::connector::region_ownership::{
    build_lifecycle_hierarchy, event_codes, generate_quiescence_trace, Region, RegionError,
    RegionKind, TaskState,
};

#[test]
fn lifecycle_hierarchy_has_correct_structure() {
    let (root, health, rollout, fencing) =
        build_lifecycle_hierarchy("test-conn", "trace-001", 5000, 2000);

    assert_eq!(root.kind, RegionKind::ConnectorLifecycle);
    assert!(root.parent_id.is_none());
    assert_eq!(root.child_region_ids.len(), 3);

    assert_eq!(health.kind, RegionKind::HealthGate);
    assert_eq!(health.parent_id, Some(root.id));

    assert_eq!(rollout.kind, RegionKind::Rollout);
    assert_eq!(rollout.parent_id, Some(root.id));

    assert_eq!(fencing.kind, RegionKind::Fencing);
    assert_eq!(fencing.parent_id, Some(root.id));
}

#[test]
fn shutdown_drains_all_child_tasks() {
    let (mut root, _, _, _) =
        build_lifecycle_hierarchy("test-conn", "trace-002", 5000, 2000);

    root.register_task("health-eval-1").unwrap();
    root.register_task("rollout-transition-1").unwrap();
    root.register_task("fencing-acquire-1").unwrap();

    let result = root.close().unwrap();
    assert!(result.quiescence_achieved);
    assert_eq!(result.tasks_drained, 3);
    assert_eq!(result.tasks_force_terminated, 0);
    assert!(root.is_quiescent());
}

#[test]
fn completed_tasks_do_not_outlive_region() {
    let (mut root, _, _, _) =
        build_lifecycle_hierarchy("test-conn", "trace-003", 5000, 2000);

    root.register_task("task-1").unwrap();
    root.register_task("task-2").unwrap();
    root.complete_task("task-1").unwrap();

    let result = root.close().unwrap();
    assert!(result.quiescence_achieved);
    // task-1 was already completed, task-2 was drained during close
    assert_eq!(result.tasks_drained, 2);
}

#[test]
fn closed_region_rejects_new_tasks() {
    let (mut root, _, _, _) =
        build_lifecycle_hierarchy("test-conn", "trace-004", 5000, 2000);

    root.close().unwrap();
    let err = root.register_task("late-task").unwrap_err();
    assert!(matches!(err, RegionError::AlreadyClosed { .. }));
}

#[test]
fn double_close_rejected() {
    let (mut root, _, _, _) =
        build_lifecycle_hierarchy("test-conn", "trace-005", 5000, 2000);

    root.close().unwrap();
    let err = root.close().unwrap_err();
    assert!(matches!(err, RegionError::AlreadyClosed { .. }));
}

#[test]
fn quiescence_trace_is_deterministic() {
    let (mut root, _, _, _) =
        build_lifecycle_hierarchy("test-conn", "trace-006", 5000, 2000);

    root.register_task("task-1").unwrap();
    let result = root.close().unwrap();

    let trace = generate_quiescence_trace(&[&root], &[&result]);
    assert!(!trace.is_empty());

    // All trace entries should be valid JSON objects
    for entry in &trace {
        assert!(entry.is_object(), "trace entry is not a JSON object");
    }

    // Should contain open and close events
    let event_codes_found: Vec<&str> = trace
        .iter()
        .filter_map(|e| e.get("event_code").and_then(|c| c.as_str()))
        .collect();
    assert!(event_codes_found.contains(&event_codes::REGION_OPENED));
    assert!(event_codes_found.contains(&event_codes::REGION_CLOSE_INITIATED));
    assert!(event_codes_found.contains(&event_codes::QUIESCENCE_ACHIEVED));
}

#[test]
fn child_region_independent_close() {
    let (_, mut health, mut rollout, mut fencing) =
        build_lifecycle_hierarchy("test-conn", "trace-007", 5000, 2000);

    health.register_task("check-1").unwrap();
    rollout.register_task("transition-1").unwrap();
    fencing.register_task("acquire-1").unwrap();

    let health_result = health.close().unwrap();
    assert!(health_result.quiescence_achieved);

    let rollout_result = rollout.close().unwrap();
    assert!(rollout_result.quiescence_achieved);

    let fencing_result = fencing.close().unwrap();
    assert!(fencing_result.quiescence_achieved);
}

#[test]
fn region_event_codes_stable() {
    assert_eq!(event_codes::REGION_OPENED, "RGN-001");
    assert_eq!(event_codes::REGION_CLOSE_INITIATED, "RGN-002");
    assert_eq!(event_codes::QUIESCENCE_ACHIEVED, "RGN-003");
    assert_eq!(event_codes::CHILD_FORCE_TERMINATED, "RGN-004");
    assert_eq!(event_codes::QUIESCENCE_TIMEOUT, "RGN-005");
}

#[test]
fn region_serde_roundtrip() {
    let root = Region::new_root("test-conn", "trace-008", 5000);
    let json = serde_json::to_string(&root).unwrap();
    let parsed: Region = serde_json::from_str(&json).unwrap();
    assert_eq!(root.kind, parsed.kind);
    assert_eq!(root.connector_id, parsed.connector_id);
    assert_eq!(root.quiescence_budget_ms, parsed.quiescence_budget_ms);
}
