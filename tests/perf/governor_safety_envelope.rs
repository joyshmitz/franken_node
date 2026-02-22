//! bd-21fo: governor safety-envelope integration/perf contract tests.

#[path = "../../crates/franken-node/src/runtime/optimization_governor.rs"]
mod optimization_governor;

use optimization_governor::{
    GovernorDecision, OptimizationGovernor, OptimizationProposal, PredictedMetrics, RuntimeKnob,
    SafetyEnvelope,
};

fn envelope() -> SafetyEnvelope {
    SafetyEnvelope {
        max_latency_ms: 120,
        min_throughput_rps: 900,
        max_error_rate_pct: 1.5,
        max_memory_mb: 512,
    }
}

fn safe_metrics() -> PredictedMetrics {
    PredictedMetrics {
        latency_ms: 95,
        throughput_rps: 1100,
        error_rate_pct: 0.8,
        memory_mb: 360,
    }
}

fn proposal(id: &str, old_value: u64, new_value: u64) -> OptimizationProposal {
    OptimizationProposal {
        proposal_id: id.to_string(),
        knob: RuntimeKnob::ConcurrencyLimit,
        old_value,
        new_value,
        predicted: safe_metrics(),
        rationale: "load test indicates safe concurrency increase".to_string(),
        trace_id: format!("trace-{id}"),
    }
}

#[test]
fn governor_applies_shadow_safe_proposal() {
    let mut governor = OptimizationGovernor::with_defaults();
    governor.update_envelope(envelope());

    let decision = governor.submit(proposal("prop-perf-1", 64, 72));
    assert_eq!(decision, GovernorDecision::Approved);
    assert_eq!(governor.knob_value(&RuntimeKnob::ConcurrencyLimit), Some(72));
}

#[test]
fn governor_rejects_candidate_that_breaks_envelope() {
    let mut governor = OptimizationGovernor::with_defaults();
    governor.update_envelope(envelope());

    let mut unsafe_proposal = proposal("prop-perf-2", 64, 88);
    unsafe_proposal.predicted = PredictedMetrics {
        latency_ms: 180,
        throughput_rps: 700,
        error_rate_pct: 2.2,
        memory_mb: 700,
    };

    let decision = governor.submit(unsafe_proposal);
    assert!(matches!(
        decision,
        GovernorDecision::Rejected(optimization_governor::RejectionReason::EnvelopeViolation(_))
    ));
}

#[test]
fn governor_auto_reverts_when_live_metrics_regress() {
    let mut governor = OptimizationGovernor::with_defaults();
    governor.update_envelope(envelope());

    let decision = governor.submit(proposal("prop-perf-3", 64, 80));
    assert_eq!(decision, GovernorDecision::Approved);
    assert_eq!(governor.knob_value(&RuntimeKnob::ConcurrencyLimit), Some(80));

    let reverted = governor.live_check(&PredictedMetrics {
        latency_ms: 170,
        throughput_rps: 980,
        error_rate_pct: 1.1,
        memory_mb: 430,
    });

    assert_eq!(reverted, vec!["prop-perf-3".to_string()]);
    assert_eq!(governor.knob_value(&RuntimeKnob::ConcurrencyLimit), Some(64));
}

#[test]
fn governor_decision_log_is_monotonic_under_multiple_proposals() {
    let mut governor = OptimizationGovernor::with_defaults();
    governor.update_envelope(envelope());

    let _ = governor.submit(proposal("prop-perf-4a", 64, 70));
    let _ = governor.submit(proposal("prop-perf-4b", 70, 74));

    let sequences = governor
        .decision_log()
        .iter()
        .map(|entry| entry.seq)
        .collect::<Vec<_>>();

    assert!(
        sequences.windows(2).all(|window| window[0] < window[1]),
        "decision sequence must be strictly increasing"
    );
}
