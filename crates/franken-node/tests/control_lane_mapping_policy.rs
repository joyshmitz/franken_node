use frankenengine_node::control_plane::control_lane_mapping::{
    ControlLane, ControlLanePolicyError, ControlLaneScheduler, default_control_lane_policy,
    error_codes, task_classes,
};

fn assert_canonical_lane_error(error: ControlLanePolicyError, task_class: &str) {
    assert_eq!(error.code(), error_codes::ERR_CLM_INCOMPLETE_MAP);
    let detail = error.to_string();
    assert!(
        detail.contains(task_class),
        "error should name downgraded task class: {detail}"
    );
    assert!(
        detail.contains("canonical task"),
        "error should describe canonical lane violation: {detail}"
    );
}

#[test]
fn validate_rejects_cancellation_handler_ready_safety_downgrade() {
    let mut policy = default_control_lane_policy();
    policy.assign(&task_classes::cancellation_handler(), ControlLane::Ready);

    let error = policy
        .validate()
        .expect_err("cancellation_handler must remain on cancel lane");
    assert_canonical_lane_error(error, "cancellation_handler");

    let scheduler_error = ControlLaneScheduler::new(policy)
        .expect_err("scheduler construction must reject wrong-lane cancellation handler");
    assert_canonical_lane_error(scheduler_error, "cancellation_handler");
}

#[test]
fn validate_rejects_lease_renewal_ready_deadline_downgrade() {
    let mut policy = default_control_lane_policy();
    policy.assign(&task_classes::lease_renewal(), ControlLane::Ready);

    let error = policy
        .validate()
        .expect_err("lease_renewal must remain on timed lane");
    assert_canonical_lane_error(error, "lease_renewal");

    let scheduler_error = ControlLaneScheduler::new(policy)
        .expect_err("scheduler construction must reject wrong-lane lease renewal");
    assert_canonical_lane_error(scheduler_error, "lease_renewal");
}
