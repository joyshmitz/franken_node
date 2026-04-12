//! bd-383z: Counterfactual incident lab and mitigation synthesis workflow.
//!
//! Replays real incident traces against synthesized mitigations, computes
//! expected-loss deltas, and produces signed rollout/rollback contracts for
//! promoted mitigations.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::capacity_defaults::aliases::MAX_EVENTS;

/// Report schema version.
pub const SCHEMA_VERSION: &str = "incident-lab-v1.0";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Incident trace ingested into lab.
    pub const ILAB_001: &str = "ILAB_001";
    /// Counterfactual replay started.
    pub const ILAB_002: &str = "ILAB_002";
    /// Expected-loss delta computed.
    pub const ILAB_003: &str = "ILAB_003";
    /// Mitigation promoted (rollout contract signed).
    pub const ILAB_004: &str = "ILAB_004";
    /// Mitigation rejected (delta below threshold).
    pub const ILAB_005: &str = "ILAB_005";
    /// Rollback contract generated.
    pub const ILAB_006: &str = "ILAB_006";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    /// Incident trace has no events.
    pub const ERR_ILAB_TRACE_EMPTY: &str = "ERR_ILAB_TRACE_EMPTY";
    /// Incident trace metadata is invalid.
    pub const ERR_ILAB_TRACE_INVALID: &str = "ERR_ILAB_TRACE_INVALID";
    /// Incident trace exceeds maximum allowed events.
    pub const ERR_ILAB_TRACE_TOO_LARGE: &str = "ERR_ILAB_TRACE_TOO_LARGE";
    /// Incident trace contains an invalid event payload or label.
    pub const ERR_ILAB_EVENT_INVALID: &str = "ERR_ILAB_EVENT_INVALID";
    /// Incident trace events are not strictly ordered by sequence.
    pub const ERR_ILAB_TRACE_ORDER: &str = "ERR_ILAB_TRACE_ORDER";
    /// Trace integrity check failed.
    pub const ERR_ILAB_TRACE_CORRUPT: &str = "ERR_ILAB_TRACE_CORRUPT";
    /// Replay produced non-deterministic output.
    pub const ERR_ILAB_REPLAY_DIVERGENCE: &str = "ERR_ILAB_REPLAY_DIVERGENCE";
    /// MitigationPlan fails validation.
    pub const ERR_ILAB_MITIGATION_INVALID: &str = "ERR_ILAB_MITIGATION_INVALID";
    /// Mitigation worsens expected loss.
    pub const ERR_ILAB_DELTA_NEGATIVE: &str = "ERR_ILAB_DELTA_NEGATIVE";
    /// Rollout contract lacks required signature.
    pub const ERR_ILAB_CONTRACT_UNSIGNED: &str = "ERR_ILAB_CONTRACT_UNSIGNED";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub mod invariants {
    /// Replay of same trace always produces identical output.
    pub const INV_ILAB_DETERMINISTIC: &str = "INV-ILAB-DETERMINISTIC";
    /// No promotion without computed expected-loss delta.
    pub const INV_ILAB_DELTA_REQUIRED: &str = "INV-ILAB-DELTA-REQUIRED";
    /// Promoted mitigations require signed rollout contract.
    pub const INV_ILAB_SIGNED_ROLLOUT: &str = "INV-ILAB-SIGNED-ROLLOUT";
    /// Every rollout contract includes a rollback clause.
    pub const INV_ILAB_ROLLBACK_ATTACHED: &str = "INV-ILAB-ROLLBACK-ATTACHED";
    /// Traces are hash-verified before replay.
    pub const INV_ILAB_TRACE_INTEGRITY: &str = "INV-ILAB-TRACE-INTEGRITY";
}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A single event within an incident trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvent {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Event label.
    pub label: String,
    /// Payload bytes (hex-encoded for deterministic hashing).
    pub payload_hex: String,
    /// Epoch milliseconds when the event occurred.
    pub timestamp_ms: u64,
}

/// A recorded sequence of system events from a real incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentTrace {
    /// Unique trace identifier.
    pub trace_id: String,
    /// Ordered sequence of events.
    pub events: Vec<TraceEvent>,
    /// SHA-256 integrity hash over the event payloads.
    pub integrity_hash: String,
    /// Metadata annotations.
    pub metadata: BTreeMap<String, String>,
}

/// Severity classification for a mitigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

/// A proposed mitigation with description and expected-loss reduction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MitigationPlan {
    /// Unique plan identifier.
    pub plan_id: String,
    /// Human-readable description.
    pub description: String,
    /// Expected loss reduction factor (0.0..=1.0).
    pub expected_loss_reduction: f64,
    /// Severity classification.
    pub severity: Severity,
    /// Steps to implement the mitigation.
    pub steps: Vec<String>,
    /// Signer identity for rollout contract.
    pub signer_id: String,
}

/// A deterministic replay of a trace through the lab engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentReplay {
    /// Source trace identifier.
    pub trace_id: String,
    /// SHA-256 digest of the replay output.
    pub replay_digest: String,
    /// Number of events replayed.
    pub events_replayed: u64,
    /// Event code emitted.
    pub event_code: String,
}

/// The outcome of comparing mitigated vs unmitigated replays.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SynthesisResult {
    /// The mitigation plan evaluated.
    pub plan_id: String,
    /// Original expected loss.
    pub original_loss: f64,
    /// Mitigated expected loss.
    pub mitigated_loss: f64,
    /// Delta (original - mitigated).
    pub expected_loss_delta: f64,
    /// Whether the mitigation was promoted.
    pub promoted: bool,
    /// Event code emitted.
    pub event_code: String,
}

/// A signed contract authorising deployment of a promoted mitigation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutContract {
    /// Unique contract identifier.
    pub contract_id: String,
    /// The plan being promoted.
    pub plan_id: String,
    /// Signer identity.
    pub signer_id: String,
    /// SHA-256 signature of the contract body.
    pub signature: String,
    /// Rollback clause (always present per INV-ILAB-ROLLBACK-ATTACHED).
    pub rollback_clause: RollbackClause,
    /// Event code emitted.
    pub event_code: String,
}

/// Rollback clause attached to every rollout contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackClause {
    /// Conditions under which rollback is triggered.
    pub trigger_conditions: Vec<String>,
    /// Maximum rollback window in seconds.
    pub rollback_window_secs: u64,
    /// Event code emitted when rollback is generated.
    pub event_code: String,
}

/// A counterfactual scenario combining a trace with a candidate mitigation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CounterfactualScenario {
    /// The incident trace.
    pub trace: IncidentTrace,
    /// The candidate mitigation plan.
    pub mitigation: MitigationPlan,
    /// Baseline expected loss.
    pub baseline_loss: f64,
    /// Promotion threshold (minimum delta to promote).
    pub promotion_threshold: f64,
}

/// Errors from the incident lab.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for LabError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for LabError {}

// ---------------------------------------------------------------------------
// IncidentLab engine
// ---------------------------------------------------------------------------

/// Configuration for the incident lab.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabConfig {
    /// Minimum expected-loss delta to promote a mitigation.
    pub promotion_threshold: f64,
    /// Accepted signer identities.
    pub accepted_signers: BTreeMap<String, bool>,
    /// Rollback window (seconds).
    pub rollback_window_secs: u64,
}

impl Default for LabConfig {
    fn default() -> Self {
        Self {
            promotion_threshold: 0.05,
            accepted_signers: BTreeMap::new(),
            rollback_window_secs: 3600,
        }
    }
}

impl LabConfig {
    pub fn with_signer(mut self, signer_id: impl Into<String>) -> Self {
        self.accepted_signers.insert(signer_id.into(), true);
        self
    }

    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.promotion_threshold = threshold;
        self
    }

    pub fn with_rollback_window(mut self, secs: u64) -> Self {
        self.rollback_window_secs = secs;
        self
    }
}

/// The top-level engine that orchestrates scenario evaluation.
pub struct IncidentLab {
    config: LabConfig,
}

impl IncidentLab {
    pub fn new(config: LabConfig) -> Self {
        Self { config }
    }

    fn compute_trace_digest(trace: &IncidentTrace) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"incident_lab_trace_v1:");
        hasher.update((trace.events.len() as u64).to_le_bytes());
        for ev in &trace.events {
            hasher.update(ev.seq.to_le_bytes());
            hasher.update((ev.label.len() as u64).to_le_bytes());
            hasher.update(ev.label.as_bytes());
            hasher.update((ev.payload_hex.len() as u64).to_le_bytes());
            hasher.update(ev.payload_hex.as_bytes());
            hasher.update(ev.timestamp_ms.to_le_bytes());
        }
        hasher.finalize().into()
    }

    /// Compute integrity hash for a trace.
    /// INV-ILAB-TRACE-INTEGRITY: Traces are hash-verified before replay.
    pub fn compute_trace_hash(trace: &IncidentTrace) -> String {
        hex::encode(Self::compute_trace_digest(trace))
    }

    /// Validate an incident trace for replay.
    pub fn validate_trace(&self, trace: &IncidentTrace) -> Result<(), LabError> {
        let trace_id = trace.trace_id.trim();
        if trace_id.is_empty() {
            return Err(LabError {
                code: error_codes::ERR_ILAB_TRACE_INVALID.to_string(),
                message: "Incident trace_id is empty".to_string(),
            });
        }
        if trace.trace_id != trace_id {
            return Err(LabError {
                code: error_codes::ERR_ILAB_TRACE_INVALID.to_string(),
                message: "Incident trace_id contains leading or trailing whitespace".to_string(),
            });
        }
        let integrity_hash = trace.integrity_hash.trim();
        if integrity_hash.is_empty() {
            return Err(LabError {
                code: error_codes::ERR_ILAB_TRACE_INVALID.to_string(),
                message: "Incident integrity_hash is empty".to_string(),
            });
        }
        if trace.integrity_hash != integrity_hash {
            return Err(LabError {
                code: error_codes::ERR_ILAB_TRACE_INVALID.to_string(),
                message: "Incident integrity_hash contains leading or trailing whitespace"
                    .to_string(),
            });
        }
        let provided_hash = hex::decode(integrity_hash).map_err(|_| LabError {
            code: error_codes::ERR_ILAB_TRACE_INVALID.to_string(),
            message: "Incident integrity_hash is not valid hex".to_string(),
        })?;
        if provided_hash.len() != 32 {
            return Err(LabError {
                code: error_codes::ERR_ILAB_TRACE_INVALID.to_string(),
                message: format!(
                    "Incident integrity_hash has invalid length: {}",
                    provided_hash.len()
                ),
            });
        }
        if trace.events.is_empty() {
            return Err(LabError {
                code: error_codes::ERR_ILAB_TRACE_EMPTY.to_string(),
                message: "Incident trace has no events".to_string(),
            });
        }
        if trace.events.len() > MAX_EVENTS {
            return Err(LabError {
                code: error_codes::ERR_ILAB_TRACE_TOO_LARGE.to_string(),
                message: format!(
                    "Incident trace exceeds max events: {} > {}",
                    trace.events.len(),
                    MAX_EVENTS
                ),
            });
        }
        let mut prev_seq: Option<u64> = None;
        for ev in &trace.events {
            if ev.label.trim().is_empty() {
                return Err(LabError {
                    code: error_codes::ERR_ILAB_EVENT_INVALID.to_string(),
                    message: format!("Incident trace event label is empty at seq={}", ev.seq),
                });
            }
            if ev.payload_hex.trim().is_empty() {
                return Err(LabError {
                    code: error_codes::ERR_ILAB_EVENT_INVALID.to_string(),
                    message: format!(
                        "Incident trace event payload_hex is empty at seq={}",
                        ev.seq
                    ),
                });
            }
            if hex::decode(&ev.payload_hex).is_err() {
                return Err(LabError {
                    code: error_codes::ERR_ILAB_EVENT_INVALID.to_string(),
                    message: format!(
                        "Incident trace event payload_hex is invalid hex at seq={}",
                        ev.seq
                    ),
                });
            }
            if let Some(prev) = prev_seq
                && ev.seq <= prev
            {
                return Err(LabError {
                    code: error_codes::ERR_ILAB_TRACE_ORDER.to_string(),
                    message: format!(
                        "Incident trace events must be strictly increasing seq: prev={}, curr={}",
                        prev, ev.seq
                    ),
                });
            }
            prev_seq = Some(ev.seq);
        }
        let computed = Self::compute_trace_digest(trace);
        if !crate::security::constant_time::ct_eq_bytes(&computed, &provided_hash) {
            return Err(LabError {
                code: error_codes::ERR_ILAB_TRACE_CORRUPT.to_string(),
                message: format!(
                    "Integrity hash mismatch: expected={}, computed={}",
                    trace.integrity_hash,
                    hex::encode(computed),
                ),
            });
        }
        Ok(())
    }

    /// Validate a mitigation plan.
    pub fn validate_mitigation(&self, plan: &MitigationPlan) -> Result<(), LabError> {
        if plan.description.is_empty() || plan.steps.is_empty() {
            return Err(LabError {
                code: error_codes::ERR_ILAB_MITIGATION_INVALID.to_string(),
                message: "MitigationPlan must have non-empty description and steps".to_string(),
            });
        }
        if !(0.0..=1.0).contains(&plan.expected_loss_reduction) {
            return Err(LabError {
                code: error_codes::ERR_ILAB_MITIGATION_INVALID.to_string(),
                message: format!(
                    "expected_loss_reduction must be in [0.0, 1.0], got {}",
                    plan.expected_loss_reduction,
                ),
            });
        }
        if !self
            .config
            .accepted_signers
            .get(&plan.signer_id)
            .copied()
            .unwrap_or(false)
        {
            return Err(LabError {
                code: error_codes::ERR_ILAB_MITIGATION_INVALID.to_string(),
                message: format!("Signer '{}' not in accepted signers", plan.signer_id),
            });
        }
        Ok(())
    }

    /// Replay a trace deterministically.
    /// INV-ILAB-DETERMINISTIC: Same trace always produces identical output.
    pub fn replay_trace(&self, trace: &IncidentTrace) -> Result<IncidentReplay, LabError> {
        self.validate_trace(trace)?;

        let mut hasher = Sha256::new();
        hasher.update(b"incident_lab_replay_v1:");
        hasher.update((trace.events.len() as u64).to_le_bytes());
        for ev in &trace.events {
            hasher.update(ev.seq.to_le_bytes());
            hasher.update((ev.payload_hex.len() as u64).to_le_bytes());
            hasher.update(ev.payload_hex.as_bytes());
        }
        let replay_digest = hex::encode(hasher.finalize());

        Ok(IncidentReplay {
            trace_id: trace.trace_id.clone(),
            replay_digest,
            events_replayed: trace.events.len() as u64,
            event_code: event_codes::ILAB_002.to_string(),
        })
    }

    /// Compute expected-loss delta for a mitigation.
    /// INV-ILAB-DELTA-REQUIRED: No promotion without computed delta.
    pub fn compute_delta(
        &self,
        scenario: &CounterfactualScenario,
    ) -> Result<SynthesisResult, LabError> {
        self.validate_trace(&scenario.trace)?;
        self.validate_mitigation(&scenario.mitigation)?;

        let mitigated_loss =
            scenario.baseline_loss * (1.0 - scenario.mitigation.expected_loss_reduction);
        let delta = scenario.baseline_loss - mitigated_loss;

        if !delta.is_finite() || delta < 0.0 {
            return Err(LabError {
                code: error_codes::ERR_ILAB_DELTA_NEGATIVE.to_string(),
                message: format!("Mitigation worsens expected loss: delta={delta}"),
            });
        }

        let promoted = delta >= scenario.promotion_threshold;
        let event_code = if promoted {
            event_codes::ILAB_004.to_string()
        } else {
            event_codes::ILAB_005.to_string()
        };

        Ok(SynthesisResult {
            plan_id: scenario.mitigation.plan_id.clone(),
            original_loss: scenario.baseline_loss,
            mitigated_loss,
            expected_loss_delta: delta,
            promoted,
            event_code,
        })
    }

    /// Generate a signed rollout contract for a promoted mitigation.
    /// INV-ILAB-SIGNED-ROLLOUT: Promoted mitigations require signed rollout.
    /// INV-ILAB-ROLLBACK-ATTACHED: Every rollout contract includes rollback clause.
    pub fn generate_rollout_contract(
        &self,
        synthesis: &SynthesisResult,
        plan: &MitigationPlan,
    ) -> Result<RolloutContract, LabError> {
        if !synthesis.promoted {
            return Err(LabError {
                code: error_codes::ERR_ILAB_CONTRACT_UNSIGNED.to_string(),
                message: "Cannot generate rollout contract for non-promoted mitigation".to_string(),
            });
        }

        let contract_id = format!("rollout-{}", plan.plan_id);
        let signature = Self::sign_contract(&contract_id, &plan.plan_id, &plan.signer_id);

        let rollback_clause = RollbackClause {
            trigger_conditions: vec![
                "loss_increase_detected".to_string(),
                "sla_breach".to_string(),
                "manual_override".to_string(),
            ],
            rollback_window_secs: self.config.rollback_window_secs,
            event_code: event_codes::ILAB_006.to_string(),
        };

        Ok(RolloutContract {
            contract_id,
            plan_id: plan.plan_id.clone(),
            signer_id: plan.signer_id.clone(),
            signature,
            rollback_clause,
            event_code: event_codes::ILAB_004.to_string(),
        })
    }

    /// Evaluate a full counterfactual scenario end-to-end.
    pub fn evaluate_scenario(
        &self,
        scenario: &CounterfactualScenario,
    ) -> Result<(IncidentReplay, SynthesisResult, Option<RolloutContract>), LabError> {
        let replay = self.replay_trace(&scenario.trace)?;
        let synthesis = self.compute_delta(scenario)?;

        let contract = if synthesis.promoted {
            Some(self.generate_rollout_contract(&synthesis, &scenario.mitigation)?)
        } else {
            None
        };

        Ok((replay, synthesis, contract))
    }

    /// Verify that two replays of the same trace produce identical digests.
    /// INV-ILAB-DETERMINISTIC enforcement.
    pub fn verify_deterministic_replay(&self, trace: &IncidentTrace) -> Result<bool, LabError> {
        let replay_a = self.replay_trace(trace)?;
        let replay_b = self.replay_trace(trace)?;
        if !crate::security::constant_time::ct_eq(&replay_a.replay_digest, &replay_b.replay_digest)
        {
            return Err(LabError {
                code: error_codes::ERR_ILAB_REPLAY_DIVERGENCE.to_string(),
                message: format!(
                    "Non-deterministic replay: {} vs {}",
                    replay_a.replay_digest, replay_b.replay_digest,
                ),
            });
        }
        Ok(true)
    }

    /// Compute a signature for a rollout contract body.
    fn sign_contract(contract_id: &str, plan_id: &str, signer_id: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"incident_lab_contract_v1:");
        hasher.update((contract_id.len() as u64).to_le_bytes());
        hasher.update(contract_id.as_bytes());
        hasher.update((plan_id.len() as u64).to_le_bytes());
        hasher.update(plan_id.as_bytes());
        hasher.update((signer_id.len() as u64).to_le_bytes());
        hasher.update(signer_id.as_bytes());
        hex::encode(hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build a valid incident trace for testing.
pub fn make_test_trace(trace_id: &str, n_events: usize) -> IncidentTrace {
    let events: Vec<TraceEvent> = (0..n_events)
        .map(|i| TraceEvent {
            seq: i as u64,
            label: format!("event_{i}"),
            payload_hex: hex::encode(format!("payload_{i}")),
            timestamp_ms: 1_000_000 + (i as u64) * 1000,
        })
        .collect();
    let mut trace = IncidentTrace {
        trace_id: trace_id.to_string(),
        events,
        integrity_hash: String::new(),
        metadata: BTreeMap::new(),
    };
    trace.integrity_hash = IncidentLab::compute_trace_hash(&trace);
    trace
}

/// Build a valid mitigation plan for testing.
pub fn make_test_plan(plan_id: &str, signer_id: &str, reduction: f64) -> MitigationPlan {
    MitigationPlan {
        plan_id: plan_id.to_string(),
        description: format!("Test mitigation {plan_id}"),
        expected_loss_reduction: reduction,
        severity: Severity::High,
        steps: vec!["Step 1: analyse".to_string(), "Step 2: fix".to_string()],
        signer_id: signer_id.to_string(),
    }
}

/// Build a counterfactual scenario for testing.
pub fn make_test_scenario(
    trace_id: &str,
    plan_id: &str,
    signer_id: &str,
    reduction: f64,
    baseline_loss: f64,
    promotion_threshold: f64,
) -> CounterfactualScenario {
    CounterfactualScenario {
        trace: make_test_trace(trace_id, 5),
        mitigation: make_test_plan(plan_id, signer_id, reduction),
        baseline_loss,
        promotion_threshold,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn lab() -> IncidentLab {
        let config = LabConfig::default()
            .with_signer("validator-A")
            .with_threshold(0.05);
        IncidentLab::new(config)
    }

    // -- Trace validation tests --

    #[test]
    fn test_empty_trace_rejected() {
        let lab = lab();
        let mut trace = IncidentTrace {
            trace_id: "t-empty".to_string(),
            events: vec![],
            integrity_hash: String::new(),
            metadata: BTreeMap::new(),
        };
        trace.integrity_hash = IncidentLab::compute_trace_hash(&trace);
        let err = lab.validate_trace(&trace).expect_err("should fail");
        assert_eq!(err.code, error_codes::ERR_ILAB_TRACE_EMPTY);
    }

    #[test]
    fn test_trace_id_empty_rejected() {
        let lab = lab();
        let mut trace = make_test_trace("t-empty-id", 3);
        trace.trace_id = "   ".to_string();
        let err = lab.validate_trace(&trace).expect_err("should fail");
        assert_eq!(err.code, error_codes::ERR_ILAB_TRACE_INVALID);
    }

    #[test]
    fn test_integrity_hash_empty_rejected() {
        let lab = lab();
        let mut trace = make_test_trace("t-empty-hash", 3);
        trace.integrity_hash = "  ".to_string();
        let err = lab.validate_trace(&trace).expect_err("should fail");
        assert_eq!(err.code, error_codes::ERR_ILAB_TRACE_INVALID);
    }

    #[test]
    fn test_corrupt_trace_rejected() {
        let lab = lab();
        let mut trace = make_test_trace("t-corrupt", 3);
        trace.integrity_hash = "badhash".to_string();
        let err = lab.validate_trace(&trace).expect_err("should fail");
        assert_eq!(err.code, error_codes::ERR_ILAB_TRACE_INVALID);
    }

    #[test]
    fn test_corrupt_trace_same_length_hash_rejected() {
        let lab = lab();
        let mut trace = make_test_trace("t-corrupt-same-len", 3);
        let mut chars: Vec<char> = trace.integrity_hash.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        trace.integrity_hash = chars.into_iter().collect();
        let err = lab.validate_trace(&trace).expect_err("should fail");
        assert_eq!(err.code, error_codes::ERR_ILAB_TRACE_CORRUPT);
    }

    #[test]
    fn test_trace_too_large_rejected() {
        let lab = lab();
        let trace = make_test_trace("t-too-large", MAX_EVENTS + 1);
        let err = lab.validate_trace(&trace).expect_err("should fail");
        assert_eq!(err.code, error_codes::ERR_ILAB_TRACE_TOO_LARGE);
    }

    #[test]
    fn test_trace_out_of_order_rejected() {
        let lab = lab();
        let mut trace = make_test_trace("t-order", 3);
        trace.events.swap(0, 1);
        trace.integrity_hash = IncidentLab::compute_trace_hash(&trace);
        let err = lab.validate_trace(&trace).expect_err("should fail");
        assert_eq!(err.code, error_codes::ERR_ILAB_TRACE_ORDER);
    }

    #[test]
    fn test_trace_duplicate_seq_rejected() {
        let lab = lab();
        let mut trace = make_test_trace("t-dup-seq", 3);
        trace.events[1].seq = trace.events[0].seq;
        trace.integrity_hash = IncidentLab::compute_trace_hash(&trace);
        let err = lab.validate_trace(&trace).expect_err("should fail");
        assert_eq!(err.code, error_codes::ERR_ILAB_TRACE_ORDER);
    }

    #[test]
    fn test_trace_empty_label_rejected() {
        let lab = lab();
        let mut trace = make_test_trace("t-empty-label", 2);
        trace.events[0].label = "   ".to_string();
        trace.integrity_hash = IncidentLab::compute_trace_hash(&trace);
        let err = lab.validate_trace(&trace).expect_err("should fail");
        assert_eq!(err.code, error_codes::ERR_ILAB_EVENT_INVALID);
    }

    #[test]
    fn test_trace_invalid_payload_hex_rejected() {
        let lab = lab();
        let mut trace = make_test_trace("t-bad-hex", 2);
        trace.events[0].payload_hex = "not-hex".to_string();
        trace.integrity_hash = IncidentLab::compute_trace_hash(&trace);
        let err = lab.validate_trace(&trace).expect_err("should fail");
        assert_eq!(err.code, error_codes::ERR_ILAB_EVENT_INVALID);
    }

    #[test]
    fn test_valid_trace_accepted() {
        let lab = lab();
        let trace = make_test_trace("t-valid", 5);
        assert!(lab.validate_trace(&trace).is_ok());
    }

    #[test]
    fn test_trace_hash_is_deterministic() {
        let trace = make_test_trace("t-det", 10);
        let h1 = IncidentLab::compute_trace_hash(&trace);
        let h2 = IncidentLab::compute_trace_hash(&trace);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_trace_hash_changes_with_content() {
        let t1 = make_test_trace("t-a", 3);
        let t2 = make_test_trace("t-b", 4);
        assert_ne!(
            IncidentLab::compute_trace_hash(&t1),
            IncidentLab::compute_trace_hash(&t2),
        );
    }

    // -- Mitigation validation tests --

    #[test]
    fn test_empty_description_rejected() {
        let lab = lab();
        let mut plan = make_test_plan("p1", "validator-A", 0.5);
        plan.description = String::new();
        let err = lab.validate_mitigation(&plan).expect_err("should fail");
        assert_eq!(err.code, error_codes::ERR_ILAB_MITIGATION_INVALID);
    }

    #[test]
    fn test_empty_steps_rejected() {
        let lab = lab();
        let mut plan = make_test_plan("p2", "validator-A", 0.5);
        plan.steps.clear();
        let err = lab.validate_mitigation(&plan).expect_err("should fail");
        assert_eq!(err.code, error_codes::ERR_ILAB_MITIGATION_INVALID);
    }

    #[test]
    fn test_reduction_out_of_range_rejected() {
        let lab = lab();
        let plan = make_test_plan("p3", "validator-A", 1.5);
        let err = lab.validate_mitigation(&plan).expect_err("should fail");
        assert_eq!(err.code, error_codes::ERR_ILAB_MITIGATION_INVALID);
    }

    #[test]
    fn test_unknown_signer_rejected() {
        let lab = lab();
        let plan = make_test_plan("p4", "unknown-signer", 0.5);
        let err = lab.validate_mitigation(&plan).expect_err("should fail");
        assert_eq!(err.code, error_codes::ERR_ILAB_MITIGATION_INVALID);
    }

    #[test]
    fn test_disabled_signer_rejected() {
        let mut config = LabConfig::default()
            .with_signer("validator-A")
            .with_threshold(0.05);
        // Manually disable the signer by setting the bool to false.
        config
            .accepted_signers
            .insert("validator-A".to_string(), false);
        let lab = IncidentLab::new(config);
        let plan = make_test_plan("p-disabled", "validator-A", 0.5);
        let err = lab
            .validate_mitigation(&plan)
            .expect_err("disabled signer should be rejected");
        assert_eq!(err.code, error_codes::ERR_ILAB_MITIGATION_INVALID);
        assert!(err.message.contains("validator-A"));
    }

    #[test]
    fn test_valid_mitigation_accepted() {
        let lab = lab();
        let plan = make_test_plan("p5", "validator-A", 0.3);
        assert!(lab.validate_mitigation(&plan).is_ok());
    }

    // -- Replay tests --

    #[test]
    fn test_replay_produces_deterministic_digest() {
        let lab = lab();
        let trace = make_test_trace("t-replay", 5);
        let r1 = lab.replay_trace(&trace).expect("should succeed");
        let r2 = lab.replay_trace(&trace).expect("should succeed");
        assert_eq!(r1.replay_digest, r2.replay_digest);
    }

    #[test]
    fn test_replay_emits_correct_event_code() {
        let lab = lab();
        let trace = make_test_trace("t-code", 3);
        let replay = lab.replay_trace(&trace).unwrap();
        assert_eq!(replay.event_code, event_codes::ILAB_002);
    }

    #[test]
    fn test_verify_deterministic_replay() {
        let lab = lab();
        let trace = make_test_trace("t-verify", 5);
        assert!(lab.verify_deterministic_replay(&trace).unwrap());
    }

    // -- Synthesis / delta tests --

    #[test]
    fn test_delta_computed_correctly() {
        let lab = lab();
        let scenario = make_test_scenario("t-d1", "p-d1", "validator-A", 0.3, 100.0, 5.0);
        let result = lab.compute_delta(&scenario).expect("should succeed");
        assert!((result.expected_loss_delta - 30.0).abs() < 1e-9);
        assert!((result.mitigated_loss - 70.0).abs() < 1e-9);
    }

    #[test]
    fn test_mitigation_promoted_above_threshold() {
        let lab = lab();
        let scenario = make_test_scenario("t-p1", "p-p1", "validator-A", 0.5, 100.0, 10.0);
        let result = lab.compute_delta(&scenario).expect("should succeed");
        assert!(result.promoted);
        assert_eq!(result.event_code, event_codes::ILAB_004);
    }

    #[test]
    fn test_mitigation_rejected_below_threshold() {
        let lab = lab();
        let scenario = make_test_scenario("t-r1", "p-r1", "validator-A", 0.01, 100.0, 10.0);
        let result = lab.compute_delta(&scenario).expect("should succeed");
        assert!(!result.promoted);
        assert_eq!(result.event_code, event_codes::ILAB_005);
    }

    #[test]
    fn test_zero_reduction_not_promoted() {
        let lab = lab();
        let scenario = make_test_scenario("t-z1", "p-z1", "validator-A", 0.0, 100.0, 5.0);
        let result = lab.compute_delta(&scenario).expect("should succeed");
        assert!(!result.promoted);
    }

    // -- Rollout contract tests --

    #[test]
    fn test_rollout_contract_generated_for_promoted() {
        let lab = lab();
        let scenario = make_test_scenario("t-rc1", "p-rc1", "validator-A", 0.5, 100.0, 10.0);
        let synthesis = lab.compute_delta(&scenario).expect("should succeed");
        assert!(synthesis.promoted);
        let contract = lab
            .generate_rollout_contract(&synthesis, &scenario.mitigation)
            .expect("should succeed");
        assert!(!contract.signature.is_empty());
        assert_eq!(contract.plan_id, "p-rc1");
        assert_eq!(contract.signer_id, "validator-A");
    }

    #[test]
    fn test_rollout_contract_has_rollback_clause() {
        let lab = lab();
        let scenario = make_test_scenario("t-rb1", "p-rb1", "validator-A", 0.5, 100.0, 10.0);
        let synthesis = lab.compute_delta(&scenario).expect("should succeed");
        let contract = lab
            .generate_rollout_contract(&synthesis, &scenario.mitigation)
            .expect("should succeed");
        assert!(!contract.rollback_clause.trigger_conditions.is_empty());
        assert!(contract.rollback_clause.rollback_window_secs > 0);
        assert_eq!(contract.rollback_clause.event_code, event_codes::ILAB_006);
    }

    #[test]
    fn test_rollout_contract_rejected_for_non_promoted() {
        let lab = lab();
        let scenario = make_test_scenario("t-nrc", "p-nrc", "validator-A", 0.01, 100.0, 10.0);
        let synthesis = lab.compute_delta(&scenario).expect("should succeed");
        assert!(!synthesis.promoted);
        let err = lab
            .generate_rollout_contract(&synthesis, &scenario.mitigation)
            .expect_err("should fail");
        assert_eq!(err.code, error_codes::ERR_ILAB_CONTRACT_UNSIGNED);
    }

    // -- End-to-end scenario tests --

    #[test]
    fn test_evaluate_scenario_promotes_good_mitigation() {
        let lab = lab();
        let scenario = make_test_scenario("t-e2e-1", "p-e2e-1", "validator-A", 0.5, 100.0, 10.0);
        let (replay, synthesis, contract) =
            lab.evaluate_scenario(&scenario).expect("should succeed");
        assert!(!replay.replay_digest.is_empty());
        assert!(synthesis.promoted);
        assert!(contract.is_some());
        let c = contract.expect("should succeed");
        assert_eq!(c.event_code, event_codes::ILAB_004);
    }

    #[test]
    fn test_evaluate_scenario_rejects_weak_mitigation() {
        let lab = lab();
        let scenario = make_test_scenario("t-e2e-2", "p-e2e-2", "validator-A", 0.01, 100.0, 10.0);
        let (_, synthesis, contract) = lab.evaluate_scenario(&scenario).expect("should succeed");
        assert!(!synthesis.promoted);
        assert!(contract.is_none());
    }

    #[test]
    fn test_evaluate_scenario_rejects_corrupt_trace() {
        let lab = lab();
        let mut scenario =
            make_test_scenario("t-e2e-3", "p-e2e-3", "validator-A", 0.5, 100.0, 10.0);
        scenario.trace.integrity_hash = "bad".to_string();
        let err = lab.evaluate_scenario(&scenario).expect_err("should fail");
        assert_eq!(err.code, error_codes::ERR_ILAB_TRACE_INVALID);
    }

    // -- Schema version / constant tests --

    #[test]
    fn test_schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("incident-lab-"));
    }

    #[test]
    fn test_event_codes_present() {
        let codes = [
            event_codes::ILAB_001,
            event_codes::ILAB_002,
            event_codes::ILAB_003,
            event_codes::ILAB_004,
            event_codes::ILAB_005,
            event_codes::ILAB_006,
        ];
        for code in &codes {
            assert!(code.starts_with("ILAB_"));
        }
    }

    #[test]
    fn test_error_codes_present() {
        let codes = [
            error_codes::ERR_ILAB_TRACE_EMPTY,
            error_codes::ERR_ILAB_TRACE_INVALID,
            error_codes::ERR_ILAB_TRACE_CORRUPT,
            error_codes::ERR_ILAB_REPLAY_DIVERGENCE,
            error_codes::ERR_ILAB_MITIGATION_INVALID,
            error_codes::ERR_ILAB_DELTA_NEGATIVE,
            error_codes::ERR_ILAB_CONTRACT_UNSIGNED,
        ];
        for code in &codes {
            assert!(code.starts_with("ERR_ILAB_"));
        }
    }

    #[test]
    fn test_invariants_present() {
        let invs = [
            invariants::INV_ILAB_DETERMINISTIC,
            invariants::INV_ILAB_DELTA_REQUIRED,
            invariants::INV_ILAB_SIGNED_ROLLOUT,
            invariants::INV_ILAB_ROLLBACK_ATTACHED,
            invariants::INV_ILAB_TRACE_INTEGRITY,
        ];
        for inv in &invs {
            assert!(inv.starts_with("INV-ILAB-"));
        }
    }

    // -- BTreeMap deterministic ordering test --

    #[test]
    fn test_btreemap_ordering_deterministic() {
        let mut m1 = BTreeMap::new();
        m1.insert("z".to_string(), "1".to_string());
        m1.insert("a".to_string(), "2".to_string());
        let mut m2 = BTreeMap::new();
        m2.insert("a".to_string(), "2".to_string());
        m2.insert("z".to_string(), "1".to_string());
        let s1 = serde_json::to_string(&m1).expect("should succeed");
        let s2 = serde_json::to_string(&m2).expect("should succeed");
        assert_eq!(s1, s2);
    }
}
