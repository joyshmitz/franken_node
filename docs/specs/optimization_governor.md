# Optimization Governor Spec

**Bead:** bd-21fo  
**Section:** 10.17

## Intent

The optimization governor adapts exposed runtime knobs while enforcing a hard
safety envelope. Every proposal is shadow-evaluated before apply, and every
reject/revert emits deterministic machine-readable evidence.

## Safety Envelope

- `max_latency_ms`: hard p99 latency cap
- `min_throughput_rps`: floor for throughput
- `max_error_rate_pct`: error ceiling in `[0.0, 100.0]`
- `max_memory_mb`: memory ceiling

## Exposed Knobs

- `concurrency_limit`
- `batch_size`
- `cache_capacity`
- `drain_timeout_ms`
- `retry_budget`

No engine-core internals are mutable by the governor.

## Decision Flow

1. Proposal submission (`GOV_001`)
2. Shadow evaluation start (`GOV_002`)
3. Approve and apply (`GOV_003`) or reject (`GOV_004`)
4. Anytime-valid live enforcement, with auto-revert on breach (`GOV_005`)
5. Envelope updates (`GOV_006`) and snapshots (`GOV_007`)

## Error Codes

- `ERR_GOV_ENVELOPE_VIOLATION`
- `ERR_GOV_NON_BENEFICIAL`
- `ERR_GOV_KNOB_LOCKED`
- `ERR_GOV_REVERT_FAILED`
- `ERR_GOV_SHADOW_TIMEOUT`
- `ERR_GOV_INVALID_PROPOSAL`

## Invariants

- `INV-GOV-ENVELOPE-NEVER-BREACHED`
- `INV-GOV-SHADOW-BEFORE-APPLY`
- `INV-GOV-EVIDENCE-ON-REJECT`
- `INV-GOV-KNOBS-ONLY`
- `INV-GOV-AUTO-REVERT`
- `INV-GOV-DETERMINISTIC-ORDER`

## bd-21fo Canonical Event Codes

- `GOVERNOR_CANDIDATE_PROPOSED`
- `GOVERNOR_SHADOW_EVAL_START`
- `GOVERNOR_SAFETY_CHECK_PASS`
- `GOVERNOR_POLICY_APPLIED`
- `GOVERNOR_POLICY_REVERTED`

## bd-21fo Canonical Error Codes

- `ERR_GOVERNOR_UNSAFE_CANDIDATE`
- `ERR_GOVERNOR_SHADOW_EVAL_FAILED`
- `ERR_GOVERNOR_BENEFIT_BELOW_THRESHOLD`
- `ERR_GOVERNOR_ENGINE_BOUNDARY_VIOLATION`
- `ERR_GOVERNOR_REVERT_FAILED`
- `ERR_GOVERNOR_KNOB_READONLY`

## bd-21fo Canonical Invariants

- `INV-GOVERNOR-SHADOW-REQUIRED`
- `INV-GOVERNOR-SAFETY-ENVELOPE`
- `INV-GOVERNOR-AUTO-REVERT`
- `INV-GOVERNOR-ENGINE-BOUNDARY`

## Required Artifacts

- `crates/franken-node/src/runtime/optimization_governor.rs`
- `crates/franken-node/src/perf/optimization_governor.rs`
- `tests/perf/governor_safety_envelope.rs`
- `artifacts/10.17/governor_decision_log.jsonl`
- `scripts/check_optimization_governor.py`
- `tests/test_check_optimization_governor.py`
- `artifacts/section_10_17/bd-21fo/verification_evidence.json`
- `artifacts/section_10_17/bd-21fo/verification_summary.md`
