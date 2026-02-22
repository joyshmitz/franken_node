# Counterfactual Incident Lab and Mitigation Synthesis (bd-383z)

## Scope

This contract defines the counterfactual incident lab for `franken_node`.
Real incident traces are replayed and compared against synthesized mitigations.
Promoted mitigations require signed rollout and rollback contracts with
expected-loss deltas that are strictly positive (i.e., the mitigation must
improve the baseline).

## Core Invariants

- `INV-LAB-REPLAY-FIDELITY`: replayed incident traces must reproduce the
  original decision sequence bit-for-bit before any mitigation is applied.
- `INV-LAB-SIGNED-ROLLOUT`: every promoted mitigation carries a signed rollout
  contract binding the operator to the stated parameters.
- `INV-LAB-ROLLBACK-CONTRACT`: every promoted mitigation carries a rollback
  contract that defines the conditions under which the mitigation is reverted.
- `INV-LAB-LOSS-DELTA-POSITIVE`: promoted mitigations must demonstrate a
  strictly positive expected-loss delta (i.e., net loss reduction).

## Incident Lab Workflow

1. **Load** incident trace from a replay bundle.
2. **Replay** under original policy to establish baseline decision sequence.
3. **Synthesize** candidate mitigations by varying policy parameters.
4. **Compare** counterfactual outcomes to baseline.
5. **Compute** expected-loss deltas for each candidate.
6. **Promote** mitigations that satisfy all invariants, attaching signed
   rollout and rollback contracts.

## Event Codes

- `LAB_INCIDENT_LOADED` -- incident trace successfully ingested.
- `LAB_MITIGATION_SYNTHESIZED` -- candidate mitigation generated.
- `LAB_REPLAY_COMPARED` -- baseline vs. counterfactual comparison completed.
- `LAB_LOSS_DELTA_COMPUTED` -- expected-loss delta calculated.
- `LAB_MITIGATION_PROMOTED` -- mitigation promoted with signed contracts.

## Error Codes

- `ERR_LAB_TRACE_CORRUPT` -- incident trace failed integrity check.
- `ERR_LAB_REPLAY_DIVERGED` -- replayed baseline diverged from recorded trace.
- `ERR_LAB_MITIGATION_UNSAFE` -- candidate mitigation violated a safety
  invariant during replay.
- `ERR_LAB_ROLLOUT_UNSIGNED` -- attempted promotion without signed rollout
  contract.
- `ERR_LAB_ROLLBACK_MISSING` -- attempted promotion without rollback contract.
- `ERR_LAB_LOSS_DELTA_NEGATIVE` -- candidate mitigation increased expected loss.

## Signed Contract Schema

### Rollout Contract

- `mitigation_id`: unique identifier for the synthesized mitigation.
- `policy_diff`: structured diff from baseline to mitigation policy.
- `expected_loss_delta`: signed integer (must be > 0 for promotion).
- `operator_id`: identity of the promoting operator.
- `signature`: cryptographic signature over the contract fields.
- `valid_from_epoch_ms`: earliest activation time.
- `valid_until_epoch_ms`: latest activation time.

### Rollback Contract

- `mitigation_id`: reference to the promoted mitigation.
- `rollback_trigger`: condition expression for automatic rollback.
- `rollback_policy`: policy to revert to on rollback.
- `operator_id`: identity of the promoting operator.
- `signature`: cryptographic signature over the contract fields.

## Required Artifacts

- `crates/franken-node/src/ops/mod.rs`
- `crates/franken-node/src/ops/mitigation_synthesis.rs`
- `tests/lab/counterfactual_mitigation_eval.rs`
- `scripts/check_counterfactual_lab.py`
- `tests/test_check_counterfactual_lab.py`
- `artifacts/10.17/counterfactual_eval_report.json`
- `artifacts/section_10_17/bd-383z/verification_evidence.json`
- `artifacts/section_10_17/bd-383z/verification_summary.md`
