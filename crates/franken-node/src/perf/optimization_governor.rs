//! bd-21fo: Self-evolving optimization governor with safety-envelope enforcement.
//!
//! This module provides the [`GovernorGate`] facade that enforces the bd-21fo
//! acceptance criteria on top of the core [`OptimizationGovernor`] from
//! `crate::runtime::optimization_governor`.
//!
//! # Acceptance Criteria (bd-21fo)
//!
//! 1. Candidate optimizations require shadow evaluation plus anytime-valid
//!    safety checks.
//! 2. Unsafe or non-beneficial policies auto-reject or auto-revert with
//!    evidence.
//! 3. The governor can only adjust exposed runtime knobs, not local
//!    engine-core internals.
//!
//! # Event Codes
//!
//! - `GOVERNOR_CANDIDATE_PROPOSED`
//! - `GOVERNOR_SHADOW_EVAL_START`
//! - `GOVERNOR_SAFETY_CHECK_PASS`
//! - `GOVERNOR_POLICY_APPLIED`
//! - `GOVERNOR_POLICY_REVERTED`
//!
//! # Error Codes
//!
//! - `ERR_GOVERNOR_UNSAFE_CANDIDATE`
//! - `ERR_GOVERNOR_SHADOW_EVAL_FAILED`
//! - `ERR_GOVERNOR_BENEFIT_BELOW_THRESHOLD`
//! - `ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION`
//! - `ERR_GOVERNOR_REVERT_FAILED`
//! - `ERR_GOVERNOR_KNOB_READONLY`
//!
//! # Invariants
//!
//! - `INV-GOVERNOR-SHADOW-REQUIRED`
//! - `INV-GOVERNOR-SAFETY-ENVELOPE`
//! - `INV-GOVERNOR-AUTO-REVERT`
//! - `INV-GOVERNOR-ENGINE-BOUNDARY`

use serde::{Deserialize, Serialize};

// Re-export the core governor and its types from the runtime module.
pub use crate::runtime::optimization_governor::{
    DecisionRecord, GovernorDecision, GovernorSnapshot, KnobState, OptimizationGovernor,
    OptimizationProposal, PredictedMetrics, RejectionReason, RuntimeKnob, SafetyEnvelope,
    ShadowResult, SCHEMA_VERSION,
    error_codes, event_codes, invariants,
};

/// A gateway audit record that uses the bd-21fo canonical event codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateAuditEntry {
    /// Which canonical event code was emitted.
    pub event_code: String,
    /// Proposal identifier.
    pub proposal_id: String,
    /// Optional detail string (e.g. rejection reason or violation list).
    pub detail: String,
}

/// A thin wrapper around [`OptimizationGovernor`] that emits bd-21fo
/// canonical event codes and enforces the engine-boundary invariant.
///
/// INV-GOVERNOR-ENGINE-BOUNDARY: the governor adjusts only exposed
/// [`RuntimeKnob`] variants; engine-core internals are unreachable by
/// construction (the [`RuntimeKnob`] enum is exhaustive over allowed
/// knobs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernorGate {
    inner: OptimizationGovernor,
    audit_trail: Vec<GateAuditEntry>,
}

impl GovernorGate {
    /// Create a new gate wrapping an [`OptimizationGovernor`].
    pub fn new(governor: OptimizationGovernor) -> Self {
        Self {
            inner: governor,
            audit_trail: Vec::new(),
        }
    }

    /// Create a gate with default settings.
    pub fn with_defaults() -> Self {
        Self::new(OptimizationGovernor::with_defaults())
    }

    /// Access the inner governor.
    pub fn inner(&self) -> &OptimizationGovernor {
        &self.inner
    }

    /// Read the gate-level audit trail.
    pub fn audit_trail(&self) -> &[GateAuditEntry] {
        &self.audit_trail
    }

    /// Submit a proposal through the gate.
    ///
    /// INV-GOVERNOR-SHADOW-REQUIRED: shadow evaluation is performed by the
    /// inner governor's `submit()` path before any knob change.
    ///
    /// INV-GOVERNOR-SAFETY-ENVELOPE: the inner governor rejects proposals
    /// whose predicted metrics breach the safety envelope.
    ///
    /// INV-GOVERNOR-AUTO-REVERT: callers may invoke [`live_check`] to
    /// trigger auto-revert of applied proposals that breach the envelope
    /// at runtime.
    pub fn submit(&mut self, proposal: OptimizationProposal) -> GovernorDecision {
        let pid = proposal.proposal_id.clone();

        // GOVERNOR_CANDIDATE_PROPOSED
        self.audit_trail.push(GateAuditEntry {
            event_code: event_codes::GOVERNOR_CANDIDATE_PROPOSED.to_string(),
            proposal_id: pid.clone(),
            detail: format!("knob={} old={} new={}", proposal.knob, proposal.old_value, proposal.new_value),
        });

        // GOVERNOR_SHADOW_EVAL_START
        self.audit_trail.push(GateAuditEntry {
            event_code: event_codes::GOVERNOR_SHADOW_EVAL_START.to_string(),
            proposal_id: pid.clone(),
            detail: "shadow evaluation starting".to_string(),
        });

        let decision = self.inner.submit(proposal);

        match &decision {
            GovernorDecision::Approved => {
                // GOVERNOR_SAFETY_CHECK_PASS
                self.audit_trail.push(GateAuditEntry {
                    event_code: event_codes::GOVERNOR_SAFETY_CHECK_PASS.to_string(),
                    proposal_id: pid.clone(),
                    detail: "all safety checks passed".to_string(),
                });
                // GOVERNOR_POLICY_APPLIED
                self.audit_trail.push(GateAuditEntry {
                    event_code: event_codes::GOVERNOR_POLICY_APPLIED.to_string(),
                    proposal_id: pid,
                    detail: "policy applied to runtime knob".to_string(),
                });
            }
            GovernorDecision::Rejected(reason) => {
                let err = match reason {
                    RejectionReason::EnvelopeViolation(_) => {
                        error_codes::ERR_GOVERNOR_UNSAFE_CANDIDATE
                    }
                    RejectionReason::NonBeneficial => {
                        error_codes::ERR_GOVERNOR_BENEFIT_BELOW_THRESHOLD
                    }
                    RejectionReason::KnobLocked => {
                        error_codes::ERR_GOVERNOR_KNOB_READONLY
                    }
                    RejectionReason::InvalidProposal(_) => {
                        error_codes::ERR_GOVERNOR_SHADOW_EVAL_FAILED
                    }
                };
                self.audit_trail.push(GateAuditEntry {
                    event_code: err.to_string(),
                    proposal_id: pid,
                    detail: format!("{reason:?}"),
                });
            }
            GovernorDecision::Reverted(msg) => {
                self.audit_trail.push(GateAuditEntry {
                    event_code: event_codes::GOVERNOR_POLICY_REVERTED.to_string(),
                    proposal_id: pid,
                    detail: msg.clone(),
                });
            }
            GovernorDecision::ShadowOnly => {}
        }

        decision
    }

    /// Perform a live safety-envelope check and auto-revert breaching policies.
    ///
    /// INV-GOVERNOR-AUTO-REVERT: any applied policy whose live metrics
    /// breach the envelope is reverted with evidence.
    pub fn live_check(&mut self, live_metrics: &PredictedMetrics) -> Vec<String> {
        let reverted = self.inner.live_check(live_metrics);
        for pid in &reverted {
            // GOVERNOR_POLICY_REVERTED
            self.audit_trail.push(GateAuditEntry {
                event_code: event_codes::GOVERNOR_POLICY_REVERTED.to_string(),
                proposal_id: pid.clone(),
                detail: "auto-reverted: live metrics breached safety envelope".to_string(),
            });
        }
        reverted
    }

    /// Attempt to set an engine-core internal knob, which must fail.
    ///
    /// INV-GOVERNOR-ENGINE-BOUNDARY: the governor cannot adjust
    /// engine-core internals.  This method always returns an error.
    pub fn reject_engine_internal_adjustment(
        &mut self,
        internal_name: &str,
    ) -> Result<(), String> {
        self.audit_trail.push(GateAuditEntry {
            event_code: error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION.to_string(),
            proposal_id: String::new(),
            detail: format!("rejected engine-core internal: {internal_name}"),
        });
        Err(format!(
            "{}: cannot adjust engine-core internal '{}'",
            error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION,
            internal_name,
        ))
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn safe_metrics() -> PredictedMetrics {
        PredictedMetrics {
            latency_ms: 200,
            throughput_rps: 500,
            error_rate_pct: 0.1,
            memory_mb: 2048,
        }
    }

    fn good_proposal(id: &str) -> OptimizationProposal {
        OptimizationProposal {
            proposal_id: id.to_string(),
            knob: RuntimeKnob::ConcurrencyLimit,
            old_value: 64,
            new_value: 128,
            predicted: safe_metrics(),
            rationale: "Increase concurrency under low load".to_string(),
            trace_id: format!("trace-{id}"),
        }
    }

    fn unsafe_proposal(id: &str) -> OptimizationProposal {
        OptimizationProposal {
            proposal_id: id.to_string(),
            knob: RuntimeKnob::BatchSize,
            old_value: 128,
            new_value: 512,
            predicted: PredictedMetrics {
                latency_ms: 800,
                throughput_rps: 50,
                error_rate_pct: 2.0,
                memory_mb: 5000,
            },
            rationale: "Aggressive batch size".to_string(),
            trace_id: format!("trace-{id}"),
        }
    }

    // --- GovernorGate tests ---

    #[test]
    fn test_gate_submit_approved_emits_candidate_proposed() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1"));
        let codes: Vec<&str> = gate.audit_trail().iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&event_codes::GOVERNOR_CANDIDATE_PROPOSED));
    }

    #[test]
    fn test_gate_submit_approved_emits_shadow_eval_start() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1"));
        let codes: Vec<&str> = gate.audit_trail().iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&event_codes::GOVERNOR_SHADOW_EVAL_START));
    }

    #[test]
    fn test_gate_submit_approved_emits_safety_check_pass() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1"));
        let codes: Vec<&str> = gate.audit_trail().iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&event_codes::GOVERNOR_SAFETY_CHECK_PASS));
    }

    #[test]
    fn test_gate_submit_approved_emits_policy_applied() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1"));
        let codes: Vec<&str> = gate.audit_trail().iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&event_codes::GOVERNOR_POLICY_APPLIED));
    }

    #[test]
    fn test_gate_unsafe_proposal_rejects_with_error_code() {
        let mut gate = GovernorGate::with_defaults();
        let decision = gate.submit(unsafe_proposal("p2"));
        assert!(matches!(decision, GovernorDecision::Rejected(RejectionReason::EnvelopeViolation(_))));
        let codes: Vec<&str> = gate.audit_trail().iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&error_codes::ERR_GOVERNOR_UNSAFE_CANDIDATE));
    }

    #[test]
    fn test_gate_non_beneficial_rejects_with_error_code() {
        let mut gate = GovernorGate::with_defaults();
        let mut p = good_proposal("p3");
        p.new_value = p.old_value; // no change
        let decision = gate.submit(p);
        assert!(matches!(decision, GovernorDecision::Rejected(RejectionReason::NonBeneficial)));
        let codes: Vec<&str> = gate.audit_trail().iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&error_codes::ERR_GOVERNOR_BENEFIT_BELOW_THRESHOLD));
    }

    #[test]
    fn test_gate_locked_knob_rejects_with_readonly_code() {
        let mut gov = OptimizationGovernor::with_defaults();
        gov.lock_knob(RuntimeKnob::ConcurrencyLimit);
        let mut gate = GovernorGate::new(gov);
        let decision = gate.submit(good_proposal("p4"));
        assert!(matches!(decision, GovernorDecision::Rejected(RejectionReason::KnobLocked)));
        let codes: Vec<&str> = gate.audit_trail().iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&error_codes::ERR_GOVERNOR_KNOB_READONLY));
    }

    #[test]
    fn test_gate_live_check_auto_reverts_emits_policy_reverted() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1"));
        let bad_live = PredictedMetrics {
            latency_ms: 999,
            throughput_rps: 10,
            error_rate_pct: 50.0,
            memory_mb: 9999,
        };
        let reverted = gate.live_check(&bad_live);
        assert_eq!(reverted, vec!["p1"]);
        let codes: Vec<&str> = gate.audit_trail().iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&event_codes::GOVERNOR_POLICY_REVERTED));
    }

    #[test]
    fn test_gate_engine_boundary_violation_rejected() {
        let mut gate = GovernorGate::with_defaults();
        let result = gate.reject_engine_internal_adjustment("engine_core::gc_threshold");
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains(error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION));
        let codes: Vec<&str> = gate.audit_trail().iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION));
    }

    #[test]
    fn test_gate_audit_trail_records_all_events() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1"));
        // Should have at least CANDIDATE_PROPOSED, SHADOW_EVAL_START, SAFETY_CHECK_PASS, POLICY_APPLIED
        assert!(gate.audit_trail().len() >= 4, "expected >= 4 audit entries, got {}", gate.audit_trail().len());
    }

    #[test]
    fn test_gate_schema_version() {
        let gate = GovernorGate::with_defaults();
        assert_eq!(gate.inner().schema_version(), SCHEMA_VERSION);
    }

    #[test]
    fn test_invariant_constants_exist() {
        // Verify the bd-21fo invariant constants are accessible
        assert_eq!(invariants::INV_GOVERNOR_SHADOW_REQUIRED, "INV-GOVERNOR-SHADOW-REQUIRED");
        assert_eq!(invariants::INV_GOVERNOR_SAFETY_ENVELOPE, "INV-GOVERNOR-SAFETY-ENVELOPE");
        assert_eq!(invariants::INV_GOVERNOR_AUTO_REVERT, "INV-GOVERNOR-AUTO-REVERT");
        assert_eq!(invariants::INV_GOVERNOR_ENGINE_BOUNDARY, "INV-GOVERNOR-ENGINE-BOUNDARY");
    }

    #[test]
    fn test_event_code_constants_exist() {
        assert_eq!(event_codes::GOVERNOR_CANDIDATE_PROPOSED, "GOVERNOR_CANDIDATE_PROPOSED");
        assert_eq!(event_codes::GOVERNOR_SHADOW_EVAL_START, "GOVERNOR_SHADOW_EVAL_START");
        assert_eq!(event_codes::GOVERNOR_SAFETY_CHECK_PASS, "GOVERNOR_SAFETY_CHECK_PASS");
        assert_eq!(event_codes::GOVERNOR_POLICY_APPLIED, "GOVERNOR_POLICY_APPLIED");
        assert_eq!(event_codes::GOVERNOR_POLICY_REVERTED, "GOVERNOR_POLICY_REVERTED");
    }

    #[test]
    fn test_error_code_constants_exist() {
        assert_eq!(error_codes::ERR_GOVERNOR_UNSAFE_CANDIDATE, "ERR_GOVERNOR_UNSAFE_CANDIDATE");
        assert_eq!(error_codes::ERR_GOVERNOR_SHADOW_EVAL_FAILED, "ERR_GOVERNOR_SHADOW_EVAL_FAILED");
        assert_eq!(error_codes::ERR_GOVERNOR_BENEFIT_BELOW_THRESHOLD, "ERR_GOVERNOR_BENEFIT_BELOW_THRESHOLD");
        assert_eq!(error_codes::ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION, "ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION");
        assert_eq!(error_codes::ERR_GOVERNOR_REVERT_FAILED, "ERR_GOVERNOR_REVERT_FAILED");
        assert_eq!(error_codes::ERR_GOVERNOR_KNOB_READONLY, "ERR_GOVERNOR_KNOB_READONLY");
    }

    #[test]
    fn test_gate_serde_roundtrip() {
        let mut gate = GovernorGate::with_defaults();
        gate.submit(good_proposal("p1"));
        let json = serde_json::to_string(&gate).expect("serialize");
        let gate2: GovernorGate = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(gate.inner().decision_log().len(), gate2.inner().decision_log().len());
        assert_eq!(gate.audit_trail().len(), gate2.audit_trail().len());
    }
}
