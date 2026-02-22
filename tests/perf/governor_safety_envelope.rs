//! bd-21fo: governor safety-envelope integration/perf contract tests.

#[path = "../../crates/franken-node/src/runtime/optimization_governor.rs"]
mod optimization_governor;

use optimization_governor::{
    OptimizationGovernor, OptimizationProposal, RuntimeKnob, RuntimeMetrics, SafetyEnvelope,
};

fn envelope() -> SafetyEnvelope {
    SafetyEnvelope {
        max_latency_ms: 120,
        min_throughput_rps: 900,
        max_error_rate_pct: 1.5,
        max_memory_mb: 512,
    }
}

fn baseline() -> RuntimeMetrics {
    RuntimeMetrics {
        latency_ms: 100,
        throughput_rps: 1000,
        error_rate_pct: 1.0,
        memory_mb: 420,
    }
}

fn proposal(id: &str, old_value: u64, new_value: u64) -> OptimizationProposal {
    OptimizationProposal {
        proposal_id: id.to_string(),
        knob: RuntimeKnob::ConcurrencyLimit,
        old_value,
        new_value,
        predicted_latency_ms: 95,
        predicted_throughput_rps: 1125,
        predicted_error_rate_pct: 0.8,
        predicted_memory_mb: 360,
        rationale: "load test indicates safe concurrency increase".to_string(),
        trace_id: format!("trace-{id}"),
    }
}

#[test]
fn governor_applies_shadow_safe_proposal() {
    let mut governor = OptimizationGovernor::new(envelope(), OptimizationGovernor::default_knob_values())
        .expect("governor");
    let submit = governor.submit_proposal(proposal("prop-perf-1", 64, 72));
    assert_eq!(format!("{:?}", submit), "ShadowOnly");

    let decision = governor.complete_shadow_evaluation(
        "prop-perf-1",
        &baseline(),
        &RuntimeMetrics {
            latency_ms: 94,
            throughput_rps: 1130,
            error_rate_pct: 0.7,
            memory_mb: 350,
        },
        false,
    );

    assert_eq!(format!("{:?}", decision), "Approved");
}

#[test]
fn governor_rejects_candidate_that_breaks_envelope() {
    let mut governor = OptimizationGovernor::new(envelope(), OptimizationGovernor::default_knob_values())
        .expect("governor");
    let _ = governor.submit_proposal(proposal("prop-perf-2", 64, 88));

    let decision = governor.complete_shadow_evaluation(
        "prop-perf-2",
        &baseline(),
        &RuntimeMetrics {
            latency_ms: 180,
            throughput_rps: 700,
            error_rate_pct: 2.2,
            memory_mb: 700,
        },
        false,
    );

    assert!(format!("{:?}", decision).starts_with("Rejected"));
}

#[test]
fn governor_auto_reverts_when_live_metrics_regress() {
    let mut governor = OptimizationGovernor::new(envelope(), OptimizationGovernor::default_knob_values())
        .expect("governor");
    let _ = governor.submit_proposal(proposal("prop-perf-3", 64, 80));
    let _ = governor.complete_shadow_evaluation(
        "prop-perf-3",
        &baseline(),
        &RuntimeMetrics {
            latency_ms: 96,
            throughput_rps: 1080,
            error_rate_pct: 0.9,
            memory_mb: 390,
        },
        false,
    );

    let decision = governor.enforce_live_safety(
        "prop-perf-3",
        &RuntimeMetrics {
            latency_ms: 170,
            throughput_rps: 980,
            error_rate_pct: 1.1,
            memory_mb: 430,
        },
    );

    assert!(format!("{:?}", decision).starts_with("Reverted"));
}

#[test]
fn governor_decision_log_is_monotonic_under_multiple_proposals() {
    let mut governor = OptimizationGovernor::new(envelope(), OptimizationGovernor::default_knob_values())
        .expect("governor");

    let _ = governor.submit_proposal(proposal("prop-perf-4a", 64, 70));
    let _ = governor.complete_shadow_evaluation(
        "prop-perf-4a",
        &baseline(),
        &RuntimeMetrics {
            latency_ms: 97,
            throughput_rps: 1040,
            error_rate_pct: 0.9,
            memory_mb: 405,
        },
        false,
    );

    let _ = governor.submit_proposal(proposal("prop-perf-4b", 70, 74));
    let _ = governor.complete_shadow_evaluation(
        "prop-perf-4b",
        &baseline(),
        &RuntimeMetrics {
            latency_ms: 96,
            throughput_rps: 1050,
            error_rate_pct: 0.9,
            memory_mb: 402,
        },
        false,
    );

    let sequences = governor
        .decision_log()
        .iter()
        .map(|entry| entry.sequence)
        .collect::<Vec<_>>();

    assert!(
        sequences.windows(2).all(|window| window[0] < window[1]),
        "decision sequence must be strictly increasing"
    );
}
