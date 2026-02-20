//! Conformance tests for bd-tyr2: control evidence replay integration.
//!
//! Verifies that every policy-influenced decision type can be replayed via the
//! canonical evidence-ledger replay validator (bd-2ona) and that DIVERGED or
//! ERROR verdicts block the control-plane gate.

use franken_node::connector::control_evidence::{
    map_decision_kind, ControlEvidenceEntry, DecisionKind, DecisionOutcome, DecisionType,
};
use franken_node::connector::control_evidence_replay::{
    build_replay_context, event_codes, map_to_ledger_kind, ControlReplayGate, ReplayVerdict,
    INV_CRG_BLOCK_DIVERGED, INV_CRG_CANONICAL, INV_CRG_COMPLETE, INV_CRG_DETERMINISTIC,
};
use franken_node::observability::evidence_ledger::DecisionKind as LedgerDecisionKind;
use franken_node::tools::evidence_replay_validator::{
    Candidate, Constraint, EvidenceReplayValidator, ReplayContext, ReplayResult,
};

// ── Event codes (local aliases for assertion) ────────────────────────────────

const RPL_001: &str = "RPL-001";
const RPL_002: &str = "RPL-002";
const RPL_003: &str = "RPL-003";
const RPL_004: &str = "RPL-004";
const RPL_005: &str = "RPL-005";

// ── Invariant constants (local aliases) ──────────────────────────────────────

const INV_RPL_CANONICAL: &str = "INV-CRG-CANONICAL";
const INV_RPL_DETERMINISTIC: &str = "INV-CRG-DETERMINISTIC";
const INV_RPL_FAIL_CLOSED: &str = "INV-CRG-BLOCK-DIVERGED";
const INV_RPL_COMPLETE: &str = "INV-CRG-COMPLETE";

// ── Helpers ──────────────────────────────────────────────────────────────────

fn make_entry(
    decision_type: DecisionType,
    outcome: DecisionOutcome,
    decision_id: &str,
    ts: u64,
) -> ControlEvidenceEntry {
    ControlEvidenceEntry {
        schema_version: "1.0".to_string(),
        decision_id: decision_id.to_string(),
        decision_type,
        decision_kind: map_decision_kind(decision_type, outcome),
        policy_inputs: vec!["test_input=true".to_string()],
        candidates_considered: vec!["candidate-a".to_string(), "candidate-b".to_string()],
        chosen_action: format!("{:?}", outcome),
        rejection_reasons: vec![],
        epoch: 42,
        trace_id: format!("trace-{decision_id}"),
        timestamp_ms: ts,
    }
}

// ── Decision type replay tests ───────────────────────────────────────────────

#[test]
fn test_replay_health_gate_eval_admit() {
    let mut gate = ControlReplayGate::new();
    let entry = make_entry(DecisionType::HealthGateEval, DecisionOutcome::Pass, "hg-001", 1000);
    let v = gate.verify_from_entry(&entry, "policy-v1");
    assert!(v.is_reproduced(), "HealthGateEval Admit should replay as REPRODUCED");
}

#[test]
fn test_replay_health_gate_eval_deny() {
    let mut gate = ControlReplayGate::new();
    let entry = make_entry(DecisionType::HealthGateEval, DecisionOutcome::Fail, "hg-002", 1000);
    let v = gate.verify_from_entry(&entry, "policy-v1");
    // Deny produces LedgerDecisionKind::Deny. The replay validator treats Deny
    // with unsatisfied constraints as Match (expected denial). Our context has
    // satisfied constraints so the chosen candidate (Deny kind) is selected.
    assert!(v.is_reproduced(), "HealthGateEval Deny should replay as REPRODUCED");
}

#[test]
fn test_replay_rollout_transition_admit() {
    let mut gate = ControlReplayGate::new();
    let entry = make_entry(DecisionType::RolloutTransition, DecisionOutcome::Proceed, "ro-001", 1000);
    let v = gate.verify_from_entry(&entry, "policy-v1");
    assert!(v.is_reproduced(), "RolloutTransition Admit should replay as REPRODUCED");
}

#[test]
fn test_replay_quarantine_action() {
    let mut gate = ControlReplayGate::new();
    let entry = make_entry(DecisionType::QuarantineAction, DecisionOutcome::Promote, "qt-001", 1000);
    let v = gate.verify_from_entry(&entry, "policy-v1");
    assert!(v.is_reproduced(), "QuarantineAction Release should replay as REPRODUCED");
}

#[test]
fn test_replay_fencing_decision_admit() {
    let mut gate = ControlReplayGate::new();
    let entry = make_entry(DecisionType::FencingDecision, DecisionOutcome::Grant, "fc-001", 1000);
    let v = gate.verify_from_entry(&entry, "policy-v1");
    assert!(v.is_reproduced(), "FencingDecision Admit should replay as REPRODUCED");
}

#[test]
fn test_replay_migration_decision_admit() {
    let mut gate = ControlReplayGate::new();
    let entry = make_entry(DecisionType::MigrationDecision, DecisionOutcome::Proceed, "mg-001", 1000);
    let v = gate.verify_from_entry(&entry, "policy-v1");
    assert!(v.is_reproduced(), "MigrationDecision Admit should replay as REPRODUCED");
}

// ── DIVERGED / ERROR tests ───────────────────────────────────────────────────

#[test]
fn test_diverged_blocks_gate() {
    let mut gate = ControlReplayGate::new();
    let entry = make_entry(DecisionType::HealthGateEval, DecisionOutcome::Pass, "hg-003", 1000);
    // Provide context where a different candidate wins
    let ctx = ReplayContext::new(
        vec![
            Candidate {
                id: "alt-winner".to_string(),
                decision_kind: LedgerDecisionKind::Deny,
                score: 1.0,
                metadata: serde_json::json!({}),
            },
            Candidate {
                id: "hg-003".to_string(),
                decision_kind: LedgerDecisionKind::Admit,
                score: 0.5,
                metadata: serde_json::json!({}),
            },
        ],
        vec![Constraint {
            id: "c1".to_string(),
            description: "test".to_string(),
            satisfied: true,
        }],
        42,
        "policy-v1",
    );
    let v = gate.verify(&entry, &ctx);
    assert!(v.is_diverged(), "Divergence should be detected");
    assert!(!gate.gate_pass(), "DIVERGED should block gate");
}

#[test]
fn test_error_blocks_gate() {
    let mut gate = ControlReplayGate::new();
    let entry = make_entry(DecisionType::HealthGateEval, DecisionOutcome::Pass, "err-001", 1000);
    // Empty candidates → invalid context → ERROR
    let ctx = ReplayContext::new(vec![], vec![], 42, "policy-v1");
    let v = gate.verify(&entry, &ctx);
    assert!(v.is_error(), "Invalid context should produce ERROR");
    assert!(!gate.gate_pass(), "ERROR should block gate");
}

#[test]
fn test_epoch_mismatch_detected() {
    let mut gate = ControlReplayGate::new();
    let entry = make_entry(DecisionType::HealthGateEval, DecisionOutcome::Pass, "hg-epoch", 1000);
    // Context epoch doesn't match entry.epoch (42 vs 999)
    let ctx = ReplayContext::new(
        vec![Candidate {
            id: "hg-epoch".to_string(),
            decision_kind: LedgerDecisionKind::Admit,
            score: 1.0,
            metadata: serde_json::json!({}),
        }],
        vec![],
        999,
        "policy-v1",
    );
    let v = gate.verify(&entry, &ctx);
    assert!(!v.is_reproduced(), "Epoch mismatch should not produce REPRODUCED");
    assert!(!gate.gate_pass(), "Epoch mismatch should block gate");
}

// ── Determinism ──────────────────────────────────────────────────────────────

#[test]
fn test_replay_deterministic_across_runs() {
    let entry = make_entry(DecisionType::HealthGateEval, DecisionOutcome::Pass, "det-001", 1000);
    let mut results = Vec::new();
    for _ in 0..50 {
        let mut gate = ControlReplayGate::new();
        let v = gate.verify_from_entry(&entry, "policy-v1");
        results.push(v.is_reproduced());
    }
    assert!(
        results.iter().all(|&r| r == results[0]),
        "Replay must be deterministic across runs"
    );
}

// ── Batch validation ─────────────────────────────────────────────────────────

#[test]
fn test_batch_validation_all_decision_types() {
    let mut gate = ControlReplayGate::new();
    let outcomes = [
        (DecisionType::HealthGateEval, DecisionOutcome::Pass),
        (DecisionType::RolloutTransition, DecisionOutcome::Proceed),
        (DecisionType::QuarantineAction, DecisionOutcome::Promote),
        (DecisionType::FencingDecision, DecisionOutcome::Grant),
        (DecisionType::MigrationDecision, DecisionOutcome::Proceed),
    ];
    for (i, (dt, outcome)) in outcomes.iter().enumerate() {
        let entry = make_entry(*dt, *outcome, &format!("batch-{i:03}"), (i as u64 + 1) * 100);
        let v = gate.verify_from_entry(&entry, "policy-v1");
        assert!(
            v.is_reproduced(),
            "{} should replay as REPRODUCED, got {}",
            dt.label(),
            v
        );
    }
    assert!(gate.gate_pass());
    assert_eq!(gate.summary().total, 5);
    assert_eq!(gate.summary().reproduced, 5);
}

// ── Event code tests ─────────────────────────────────────────────────────────

#[test]
fn test_event_codes_defined() {
    assert_eq!(RPL_001, event_codes::RPL_001_REPLAY_INITIATED);
    assert_eq!(RPL_002, event_codes::RPL_002_REPRODUCED);
    assert_eq!(RPL_003, event_codes::RPL_003_DIVERGED);
    assert_eq!(RPL_004, event_codes::RPL_004_ERROR);
    assert_eq!(RPL_005, event_codes::RPL_005_GATE_DECISION);
}

#[test]
fn test_replay_event_codes_from_validator() {
    use franken_node::tools::evidence_replay_validator::event_codes as erv;
    assert_eq!(erv::REPLAY_START, "EVD-REPLAY-001");
    assert_eq!(erv::REPLAY_MATCH, "EVD-REPLAY-002");
    assert_eq!(erv::REPLAY_MISMATCH, "EVD-REPLAY-003");
    assert_eq!(erv::REPLAY_UNRESOLVABLE, "EVD-REPLAY-004");
}

// ── Invariant tests ──────────────────────────────────────────────────────────

#[test]
fn test_invariant_canonical_validator() {
    // INV-CRG-CANONICAL: gate uses EvidenceReplayValidator, not custom logic
    assert_eq!(INV_RPL_CANONICAL, INV_CRG_CANONICAL);
}

#[test]
fn test_invariant_deterministic() {
    assert_eq!(INV_RPL_DETERMINISTIC, INV_CRG_DETERMINISTIC);
}

#[test]
fn test_invariant_fail_closed() {
    assert_eq!(INV_RPL_FAIL_CLOSED, INV_CRG_BLOCK_DIVERGED);
}

#[test]
fn test_invariant_complete() {
    assert_eq!(INV_RPL_COMPLETE, INV_CRG_COMPLETE);
}

// ── Summary report ───────────────────────────────────────────────────────────

#[test]
fn test_summary_report_after_batch() {
    let mut gate = ControlReplayGate::new();
    let entry = make_entry(DecisionType::HealthGateEval, DecisionOutcome::Pass, "sum-001", 1000);
    gate.verify_from_entry(&entry, "policy-v1");
    let s = gate.summary();
    assert_eq!(s.total, 1);
    assert!(s.gate_pass());
}

#[test]
fn test_gate_verdict_match_passes() {
    let mut gate = ControlReplayGate::new();
    let entry = make_entry(DecisionType::HealthGateEval, DecisionOutcome::Pass, "vp-001", 1000);
    let v = gate.verify_from_entry(&entry, "policy-v1");
    assert!(v.is_reproduced());
    assert!(gate.gate_pass());
}
