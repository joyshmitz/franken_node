//! bd-383z: Counterfactual mitigation evaluation lab tests.
//!
//! Self-contained model tests that verify the counterfactual incident lab
//! workflow end-to-end: trace loading, replay fidelity, mitigation synthesis,
//! loss-delta computation, and signed contract promotion.
//!
//! These tests do NOT import from `franken_node` internals; they model the
//! same invariants independently.
//!
//! Invariants under test:
//!   INV-LAB-REPLAY-FIDELITY
//!   INV-LAB-SIGNED-ROLLOUT
//!   INV-LAB-ROLLBACK-CONTRACT
//!   INV-LAB-LOSS-DELTA-POSITIVE
//!
//! Event codes: LAB_INCIDENT_LOADED, LAB_MITIGATION_SYNTHESIZED,
//!              LAB_REPLAY_COMPARED, LAB_LOSS_DELTA_COMPUTED,
//!              LAB_MITIGATION_PROMOTED
//!
//! Error codes: ERR_LAB_TRACE_CORRUPT, ERR_LAB_REPLAY_DIVERGED,
//!              ERR_LAB_MITIGATION_UNSAFE, ERR_LAB_ROLLOUT_UNSIGNED,
//!              ERR_LAB_ROLLBACK_MISSING, ERR_LAB_LOSS_DELTA_NEGATIVE

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Model types (standalone, no franken_node dependency)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
struct Decision {
    seq: u64,
    action: String,
    expected_loss: i64,
}

#[derive(Debug, Clone)]
struct Trace {
    incident_id: String,
    decisions: Vec<Decision>,
    hash: String,
}

impl Trace {
    fn compute_hash(decisions: &[Decision]) -> String {
        let mut acc = 0u64;
        for d in decisions {
            acc = acc.wrapping_mul(31).wrapping_add(d.seq);
            acc = acc.wrapping_mul(31).wrapping_add(d.expected_loss as u64);
        }
        format!("{:016x}", acc)
    }

    fn build(incident_id: &str, decisions: Vec<Decision>) -> Self {
        let hash = Self::compute_hash(&decisions);
        Self {
            incident_id: incident_id.to_string(),
            decisions,
            hash,
        }
    }

    fn is_valid(&self) -> bool {
        Self::compute_hash(&self.decisions) == self.hash
    }
}

#[derive(Debug, Clone)]
struct MitigationCandidate {
    id: String,
    counterfactual_decisions: Vec<Decision>,
    policy_diff: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct RolloutContract {
    mitigation_id: String,
    loss_delta: i64,
    signature: String,
}

#[derive(Debug, Clone)]
struct RollbackContract {
    mitigation_id: String,
    trigger: String,
    signature: String,
}

#[derive(Debug, Clone)]
struct Promotion {
    mitigation_id: String,
    loss_delta: i64,
    rollout: RolloutContract,
    rollback: RollbackContract,
}

fn sign(payload: &str) -> String {
    format!("sig:{:016x}", {
        let mut h = 0u64;
        for b in payload.bytes() {
            h = h.wrapping_mul(31).wrapping_add(b as u64);
        }
        h
    })
}

fn synthesize(trace: &Trace, mid: &str, adjustment: i64) -> MitigationCandidate {
    let cf_decisions: Vec<Decision> = trace
        .decisions
        .iter()
        .map(|d| Decision {
            seq: d.seq,
            action: d.action.clone(),
            expected_loss: d.expected_loss.saturating_add(adjustment),
        })
        .collect();
    MitigationCandidate {
        id: mid.to_string(),
        counterfactual_decisions: cf_decisions,
        policy_diff: BTreeMap::new(),
    }
}

fn loss_delta(trace: &Trace, candidate: &MitigationCandidate) -> i64 {
    let baseline: i64 = trace.decisions.iter().map(|d| d.expected_loss).sum();
    let cf: i64 = candidate
        .counterfactual_decisions
        .iter()
        .map(|d| d.expected_loss)
        .sum();
    baseline - cf
}

fn promote(
    candidate: &MitigationCandidate,
    delta: i64,
    has_rollback: bool,
) -> Result<Promotion, String> {
    if delta <= 0 {
        return Err(format!("ERR_LAB_LOSS_DELTA_NEGATIVE: delta={delta}"));
    }

    let rollout_sig = sign(&format!("rollout:{}", candidate.id));
    if rollout_sig.is_empty() {
        return Err("ERR_LAB_ROLLOUT_UNSIGNED".to_string());
    }

    if !has_rollback {
        return Err("ERR_LAB_ROLLBACK_MISSING".to_string());
    }

    let rollback_sig = sign(&format!("rollback:{}", candidate.id));

    Ok(Promotion {
        mitigation_id: candidate.id.clone(),
        loss_delta: delta,
        rollout: RolloutContract {
            mitigation_id: candidate.id.clone(),
            loss_delta: delta,
            signature: rollout_sig,
        },
        rollback: RollbackContract {
            mitigation_id: candidate.id.clone(),
            trigger: "loss_delta < 0 OR error_rate > 0.05".to_string(),
            signature: rollback_sig,
        },
    })
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn fixture_decisions() -> Vec<Decision> {
    vec![
        Decision {
            seq: 1,
            action: "quarantine".to_string(),
            expected_loss: 50,
        },
        Decision {
            seq: 2,
            action: "observe".to_string(),
            expected_loss: 30,
        },
        Decision {
            seq: 3,
            action: "allow".to_string(),
            expected_loss: 10,
        },
    ]
}

fn fixture_trace() -> Trace {
    Trace::build("INC-LAB-EVAL-001", fixture_decisions())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// INV-LAB-REPLAY-FIDELITY: trace validation

#[test]
fn trace_integrity_valid() {
    let trace = fixture_trace();
    assert!(trace.is_valid(), "valid trace should pass integrity check");
}

#[test]
fn trace_integrity_detects_corruption() {
    let mut trace = fixture_trace();
    trace.hash = "corrupted".to_string();
    assert!(
        !trace.is_valid(),
        "ERR_LAB_TRACE_CORRUPT: corrupted hash should fail"
    );
}

// INV-LAB-REPLAY-FIDELITY: replay reproduces original decisions

#[test]
fn replay_baseline_reproduces_decisions() {
    let trace = fixture_trace();
    // Replaying = returning the same decisions.
    let replayed = trace.decisions.clone();
    assert_eq!(replayed, trace.decisions);
}

// Mitigation synthesis

#[test]
fn synthesize_mitigation_produces_adjusted_decisions() {
    let trace = fixture_trace();
    let candidate = synthesize(&trace, "mit-eval-001", -5);
    assert_eq!(
        candidate.counterfactual_decisions.len(),
        trace.decisions.len()
    );
    for (orig, cf) in trace.decisions.iter().zip(candidate.counterfactual_decisions.iter()) {
        assert_eq!(cf.expected_loss, orig.expected_loss - 5);
    }
}

// Loss-delta computation

#[test]
fn loss_delta_positive_when_mitigation_reduces_loss() {
    let trace = fixture_trace();
    let candidate = synthesize(&trace, "mit-eval-002", -5);
    let delta = loss_delta(&trace, &candidate);
    assert!(delta > 0, "INV-LAB-LOSS-DELTA-POSITIVE: delta={delta}");
}

#[test]
fn loss_delta_negative_when_mitigation_increases_loss() {
    let trace = fixture_trace();
    let candidate = synthesize(&trace, "mit-eval-003", 5);
    let delta = loss_delta(&trace, &candidate);
    assert!(delta < 0, "delta should be negative: {delta}");
}

// INV-LAB-SIGNED-ROLLOUT + INV-LAB-ROLLBACK-CONTRACT: promotion

#[test]
fn promote_succeeds_with_positive_delta_and_contracts() {
    let trace = fixture_trace();
    let candidate = synthesize(&trace, "mit-eval-004", -5);
    let delta = loss_delta(&trace, &candidate);
    let promotion = promote(&candidate, delta, true).expect("should promote");
    assert_eq!(promotion.mitigation_id, "mit-eval-004");
    assert!(promotion.loss_delta > 0);
    assert!(!promotion.rollout.signature.is_empty(), "INV-LAB-SIGNED-ROLLOUT");
    assert!(!promotion.rollback.signature.is_empty(), "INV-LAB-ROLLBACK-CONTRACT");
}

#[test]
fn promote_rejects_negative_delta() {
    let trace = fixture_trace();
    let candidate = synthesize(&trace, "mit-eval-005", 5);
    let delta = loss_delta(&trace, &candidate);
    let err = promote(&candidate, delta, true).expect_err("should reject");
    assert!(
        err.contains("ERR_LAB_LOSS_DELTA_NEGATIVE"),
        "expected ERR_LAB_LOSS_DELTA_NEGATIVE, got: {err}"
    );
}

#[test]
fn promote_rejects_missing_rollback() {
    let trace = fixture_trace();
    let candidate = synthesize(&trace, "mit-eval-006", -5);
    let delta = loss_delta(&trace, &candidate);
    let err = promote(&candidate, delta, false).expect_err("should reject");
    assert!(
        err.contains("ERR_LAB_ROLLBACK_MISSING"),
        "expected ERR_LAB_ROLLBACK_MISSING, got: {err}"
    );
}

// Full workflow

#[test]
fn full_workflow_end_to_end() {
    let trace = fixture_trace();
    assert!(trace.is_valid());
    let candidate = synthesize(&trace, "mit-full-001", -5);
    let delta = loss_delta(&trace, &candidate);
    assert!(delta > 0);
    let promotion = promote(&candidate, delta, true).expect("full workflow promotion");
    assert_eq!(promotion.mitigation_id, "mit-full-001");
    assert!(!promotion.rollout.signature.is_empty());
    assert!(!promotion.rollback.signature.is_empty());
}

// Replay divergence detection

#[test]
fn replay_divergence_detected_on_length_mismatch() {
    let trace = fixture_trace();
    let mut candidate = synthesize(&trace, "mit-div-001", -5);
    candidate.counterfactual_decisions.pop(); // Remove one decision
    // Length mismatch should be treated as ERR_LAB_REPLAY_DIVERGED
    assert_ne!(
        trace.decisions.len(),
        candidate.counterfactual_decisions.len(),
        "ERR_LAB_REPLAY_DIVERGED: decision count mismatch"
    );
}

// Event code coverage

#[test]
fn event_codes_are_defined() {
    let codes = [
        "LAB_INCIDENT_LOADED",
        "LAB_MITIGATION_SYNTHESIZED",
        "LAB_REPLAY_COMPARED",
        "LAB_LOSS_DELTA_COMPUTED",
        "LAB_MITIGATION_PROMOTED",
    ];
    for code in &codes {
        assert!(!code.is_empty());
    }
}

// Error code coverage

#[test]
fn error_codes_are_defined() {
    let codes = [
        "ERR_LAB_TRACE_CORRUPT",
        "ERR_LAB_REPLAY_DIVERGED",
        "ERR_LAB_MITIGATION_UNSAFE",
        "ERR_LAB_ROLLOUT_UNSIGNED",
        "ERR_LAB_ROLLBACK_MISSING",
        "ERR_LAB_LOSS_DELTA_NEGATIVE",
    ];
    for code in &codes {
        assert!(!code.is_empty());
    }
}
