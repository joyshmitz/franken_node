# bd-3hw: Remote Idempotency and Saga Semantics Integration

## Purpose

Integrate canonical remote idempotency with saga semantics so that every
remote effect in a multi-step workflow is named, idempotent,
capability-gated, and saga-wrapped. This closes the gap between
individual idempotency primitives and the saga executor, ensuring that
retries, compensations, and capability checks compose correctly across
multi-step remote workflows.

## Section

10.11

## Status

Implemented

## Dependencies

- **bd-12n3** -- Idempotency key derivation (canonical key generation for
  remote operations)
- **bd-206h** -- Deduplicate store (idempotency cache for at-most-once
  delivery)
- **bd-ac83** -- Computation registry (named remote computations with
  schema validation)
- **bd-1nfu** -- RemoteCap (capability-gated remote invocations)
- **bd-3h63** -- Saga wrappers with deterministic compensations (generic
  saga executor)

## Contract Summary

Every remote effect in a multi-step workflow MUST be:

1. **Named** -- registered in the computation registry (bd-ac83) with a
   stable computation name.
2. **Idempotent** -- assigned an idempotency key derived from canonical
   inputs (bd-12n3) and deduplicated through the idempotency store
   (bd-206h).
3. **Capability-gated** -- executed only when the caller holds a valid
   RemoteCap for the target computation (bd-1nfu).
4. **Saga-wrapped** -- enrolled as a `SagaStepDef` in a `SagaInstance`
   managed by the `SagaExecutor` (bd-3h63), with a matching compensating
   action that reverses the effect on failure.

The integration layer validates these four properties at saga creation
time (fail-fast) and again at step execution time (defense-in-depth).
Violations are recorded as structured events and the saga is aborted.

## Interface Boundary

- **Module:** `connector::saga` (extended with remote-idempotency
  integration)
- **Crate path:** `crates/franken-node/src/connector/saga.rs`

### Key Types

#### `SagaStepDef`

Extended step definition carrying:
- `name` -- human-readable step name
- `computation_name` -- registry name of the remote computation
- `is_remote` -- whether the step invokes a remote call
- `idempotency_key` -- canonical idempotency key for safe retries

#### `SagaExecutor`

Manages saga lifecycle (create, execute, commit, compensate) with
full audit trail and deterministic compensation ordering.

#### `SagaInstance`

Tracks step definitions, execution state, and chronological records
for a single multi-step workflow.

#### `CompensationTrace`

Replay-safe record of all compensation actions for a saga, exported
for audit and deterministic replay.

#### `StepOutcome`

Enumeration of forward-step outcomes: Success, Failed, Skipped,
Compensated.

#### `SagaState`

Lifecycle states: Pending, Running, Committed, Compensating,
Compensated, Failed.

## Event Codes

| Code | Event |
|------|-------|
| `FN-SG-001` | `SAGA_CREATED` -- saga instance registered with step definitions |
| `FN-SG-002` | `SAGA_STEP_FORWARD` -- a forward step executed |
| `FN-SG-003` | `SAGA_STEP_COMPENSATED` -- a compensation action executed for a step |
| `FN-SG-004` | `SAGA_COMMITTED` -- all forward steps completed; saga committed |
| `FN-SG-005` | `SAGA_COMPENSATED` -- all compensations completed; saga rolled back |
| `FN-SG-006` | `SAGA_COMPENSATION_FAILURE` -- a compensation action itself failed |
| `FN-SG-007` | `SAGA_STEP_SKIPPED` -- a forward step was skipped |
| `FN-SG-008` | `SAGA_TRACE_EXPORTED` -- compensation trace exported for audit |
| `FN-SG-009` | `SAGA_IDEMPOTENCY_HIT` -- idempotency cache returned a prior result |
| `FN-SG-010` | `SAGA_REMOTE_CAP_VALIDATED` -- RemoteCap validated for a remote step |
| `FN-SG-011` | `SAGA_REMOTE_CAP_VIOLATION` -- RemoteCap missing or invalid for a remote step |
| `FN-SG-012` | `SAGA_BULKHEAD_APPLIED` -- bulkhead isolation applied to remote step |

## Invariants

| ID | Description |
|----|-------------|
| `INV-SG-IDEMPOTENT` | Every remote step carries a canonical idempotency key; replaying the same key returns the cached result without re-execution |
| `INV-SG-ORDERED-COMPENSATION` | Compensations execute in strict reverse order of completed forward steps; no reordering is possible |
| `INV-SG-REMOTE-CAP` | Every remote step is validated against the caller's RemoteCap before execution; missing or invalid capabilities abort the saga |
| `INV-SG-BULKHEAD-SAFE` | Remote steps execute within a bulkhead boundary; a slow or failing remote call cannot block unrelated sagas |

## Acceptance Criteria

1. Every `SagaStepDef` with `is_remote = true` carries a non-empty
   `idempotency_key` and `computation_name`.
2. The `SagaExecutor` validates idempotency keys and computation names
   at saga creation time; invalid definitions are rejected.
3. Compensations execute in strict reverse order of forward steps,
   as verified by the `CompensationTrace` record.
4. RemoteCap violations are recorded via `FN-SG-011` and abort the
   saga immediately.
5. The idempotency cache returns cached results for duplicate keys
   without re-executing the remote computation.
6. Bulkhead isolation prevents a single slow remote call from blocking
   other sagas in the executor.
7. The gate script `scripts/check_remote_idempotency_saga.py` passes
   all checks with zero remote-cap violations.

## Artifacts

- Implementation: `crates/franken-node/src/connector/saga.rs`
- Spec contract: `docs/specs/section_10_11/bd-3hw_contract.md`
- Gate script: `scripts/check_remote_idempotency_saga.py`
- Tests: `tests/test_check_remote_idempotency_saga.py`
- Evidence: `artifacts/section_10_11/bd-3hw/verification_evidence.json`
- Summary: `artifacts/section_10_11/bd-3hw/verification_summary.md`
