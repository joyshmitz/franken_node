use frankenengine_node::runtime::lane_scheduler::{
    LaneConfig, LaneMappingPolicy, LaneScheduler, LaneSchedulerError, SchedulerLane, error_codes,
    event_codes, task_classes,
};

fn single_background_lane_policy() -> LaneMappingPolicy {
    let mut policy = LaneMappingPolicy::new();
    policy
        .add_lane(LaneConfig::new(SchedulerLane::Background, 10, 1))
        .expect("test lane should be unique");
    policy.add_rule(&task_classes::log_rotation(), SchedulerLane::Background);
    policy
}

fn queued_task_id_from(error: LaneSchedulerError) -> Option<String> {
    match error {
        LaneSchedulerError::CapExceeded { queued_task_id, .. } => queued_task_id,
        _ => None,
    }
}

#[test]
fn lane_scheduler_keeps_capped_task_identity_and_promotes_fifo() {
    let mut scheduler = LaneScheduler::new(single_background_lane_policy())
        .expect("test policy should construct scheduler");

    let active = scheduler
        .assign_task(&task_classes::log_rotation(), 1_000, "trace-active")
        .expect("first task should occupy the lane");
    let cap_error = scheduler
        .assign_task(&task_classes::log_rotation(), 1_001, "trace-queued")
        .expect_err("second task should queue and surface cap pressure");

    let queued_task_id = queued_task_id_from(cap_error);
    assert!(queued_task_id.is_some(), "cap error must include queued task id");
    let queued_task_id = queued_task_id.unwrap_or_default();
    assert_eq!(
        scheduler.queued_task_ids(SchedulerLane::Background),
        vec![queued_task_id.clone()]
    );
    let counters = scheduler
        .lane_counter(SchedulerLane::Background)
        .expect("background counters");
    assert_eq!(counters.queued_count, 1);
    assert_eq!(counters.first_queued_at_ms, Some(1_001));
    assert_eq!(counters.rejected_total, 1);

    scheduler
        .complete_task(&active.task_id, 1_010, "trace-complete")
        .expect("completion should promote queued task");

    assert!(scheduler.queued_task_ids(SchedulerLane::Background).is_empty());
    assert_eq!(
        scheduler.active_task_ids(SchedulerLane::Background),
        vec![queued_task_id.clone()]
    );
    let counters = scheduler
        .lane_counter(SchedulerLane::Background)
        .expect("background counters after promotion");
    assert_eq!(counters.active_count, 1);
    assert_eq!(counters.queued_count, 0);
    assert_eq!(counters.first_queued_at_ms, None);

    let queued_record = scheduler
        .audit_log()
        .iter()
        .find(|record| record.event_code == event_codes::LANE_TASK_QUEUED)
        .expect("queue audit record");
    assert_eq!(queued_record.task_id, queued_task_id);
    let promoted_record = scheduler
        .audit_log()
        .iter()
        .find(|record| record.event_code == event_codes::LANE_TASK_PROMOTED)
        .expect("promotion audit record");
    assert_eq!(promoted_record.task_id, queued_task_id);
}

#[test]
fn lane_scheduler_aborts_specific_queued_task_without_dropping_neighbors() {
    let mut scheduler = LaneScheduler::new(single_background_lane_policy())
        .expect("test policy should construct scheduler");

    scheduler
        .assign_task(&task_classes::log_rotation(), 2_000, "trace-active")
        .expect("first task should occupy the lane");
    let first_queued = queued_task_id_from(
        scheduler
            .assign_task(&task_classes::log_rotation(), 2_001, "trace-queued-1")
            .expect_err("first queued task should surface cap pressure"),
    );
    assert!(
        first_queued.is_some(),
        "first cap error must include queued task id"
    );
    let first_queued = first_queued.unwrap_or_default();
    let second_queued = queued_task_id_from(
        scheduler
            .assign_task(&task_classes::log_rotation(), 2_002, "trace-queued-2")
            .expect_err("second queued task should surface cap pressure"),
    );
    assert!(
        second_queued.is_some(),
        "second cap error must include queued task id"
    );
    let second_queued = second_queued.unwrap_or_default();

    let aborted = scheduler
        .abort_queued_task_id(&second_queued, 2_003, "trace-abort")
        .expect("specific queued task should abort");

    assert_eq!(aborted.task_id, second_queued);
    assert_eq!(
        scheduler.queued_task_ids(SchedulerLane::Background),
        vec![first_queued]
    );
    assert_eq!(
        scheduler
            .abort_queued_task_id("missing-task", 2_004, "trace-missing")
            .expect_err("missing queued task must fail")
            .code(),
        error_codes::ERR_LANE_TASK_NOT_FOUND
    );
    let counters = scheduler
        .lane_counter(SchedulerLane::Background)
        .expect("background counters");
    assert_eq!(counters.active_count, 1);
    assert_eq!(counters.queued_count, 1);
    assert_eq!(counters.first_queued_at_ms, Some(2_001));
}
