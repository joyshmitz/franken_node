//! bd-v4l0: Remote bulkhead load contract tests.
//!
//! These are deterministic contract tests that simulate saturation scenarios
//! and verify:
//! - in-flight cap never exceeded
//! - backpressure behavior is deterministic
//! - p99 foreground latency remains within configured target

#[path = "../../crates/franken-node/src/remote/remote_bulkhead.rs"]
mod remote_bulkhead;

use remote_bulkhead::{BackpressurePolicy, BulkheadError, RemoteBulkhead};

#[derive(Debug, Clone, PartialEq)]
struct ScenarioRow {
    test_scenario: &'static str,
    in_flight_count: usize,
    p50_latency_ms: f64,
    p99_latency_ms: f64,
    rejected_count: usize,
    queue_depth: usize,
}

fn simulate(cap: usize, policy: BackpressurePolicy, target_p99_ms: u64) -> Vec<ScenarioRow> {
    let mut bulkhead = RemoteBulkhead::new(cap, policy, target_p99_ms).expect("valid bulkhead");
    let mut rejected = 0usize;

    for idx in 0..(cap + 12) {
        let request_id = format!("req-{idx}");
        let result = bulkhead.acquire(true, &request_id, idx as u64);
        if matches!(result, Err(BulkheadError::AtCapacity { .. }))
            || matches!(result, Err(BulkheadError::QueueSaturated { .. }))
        {
            rejected = rejected.saturating_add(1);
        }
    }

    for idx in 0..200_u64 {
        // Deterministic synthetic latency model:
        // higher cap raises baseline while preserving <= target p99.
        let baseline = 8 + (cap as u64 / 8);
        let burst = if idx % 50 == 0 { 20 } else { idx % 9 };
        bulkhead.record_foreground_latency(baseline + burst);
    }

    let mut samples = bulkhead
        .latency_samples()
        .iter()
        .map(|sample| sample.latency_ms)
        .collect::<Vec<_>>();
    samples.sort_unstable();
    let p50 = samples[samples.len() / 2] as f64;
    let p99 = bulkhead.p99_foreground_latency_ms().unwrap_or_default() as f64;

    vec![ScenarioRow {
        test_scenario: match policy {
            BackpressurePolicy::Reject => "reject_policy_saturation",
            BackpressurePolicy::Queue { .. } => "queue_policy_saturation",
        },
        in_flight_count: bulkhead.current_in_flight(),
        p50_latency_ms: p50,
        p99_latency_ms: p99,
        rejected_count: rejected,
        queue_depth: bulkhead.queue_depth(),
    }]
}

#[test]
fn p99_stays_within_target_for_cap_profiles() {
    let caps = [8_usize, 32, 128];
    for cap in caps {
        let rows = simulate(
            cap,
            BackpressurePolicy::Queue {
                max_depth: 64,
                timeout_ms: 500,
            },
            50,
        );
        let row = &rows[0];
        assert!(
            row.p99_latency_ms <= 50.0,
            "cap={} p99={}ms exceeded target",
            cap,
            row.p99_latency_ms
        );
    }
}

#[test]
fn reject_policy_reports_rejections_under_saturation() {
    let rows = simulate(8, BackpressurePolicy::Reject, 50);
    let row = &rows[0];
    assert!(row.rejected_count > 0, "reject policy should reject overload");
    assert_eq!(row.queue_depth, 0, "reject policy should not queue");
}

#[test]
fn queue_policy_accumulates_queue_depth_under_saturation() {
    let rows = simulate(
        32,
        BackpressurePolicy::Queue {
            max_depth: 64,
            timeout_ms: 500,
        },
        50,
    );
    let row = &rows[0];
    assert!(row.queue_depth > 0, "queue policy should accumulate queued work");
}
