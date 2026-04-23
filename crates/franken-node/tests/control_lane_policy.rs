#[path = "../../../tests/conformance/control_lane_policy.rs"]
mod control_lane_policy;

use frankenengine_node::control_plane::control_lane_policy::ControlLanePolicy;

#[test]
fn one_slot_tick_prefers_timed_over_ready_when_cancel_empty() {
    let mut policy = ControlLanePolicy::new();

    let metrics = policy.tick(0, 1, 1, 1, "trace-one-slot-timed");

    assert_eq!(metrics.cancel_lane_tasks_run, 0);
    assert_eq!(metrics.timed_lane_tasks_run, 1);
    assert_eq!(metrics.ready_lane_tasks_run, 0);
    assert!(!metrics.timed_lane_starved);
    assert!(metrics.ready_lane_starved);
}

#[test]
fn two_slot_tick_serves_cancel_and_timed_before_ready() {
    let mut policy = ControlLanePolicy::new();

    let metrics = policy.tick(1, 1, 1, 2, "trace-two-slot-priority");

    assert_eq!(metrics.cancel_lane_tasks_run, 1);
    assert_eq!(metrics.timed_lane_tasks_run, 1);
    assert_eq!(metrics.ready_lane_tasks_run, 0);
    assert!(!metrics.cancel_lane_starved);
    assert!(!metrics.timed_lane_starved);
    assert!(metrics.ready_lane_starved);
}
