# bd-3h63 Contract: Saga Wrappers with Deterministic Compensations

**Bead:** bd-3h63
**Section:** 10.15 (Multi-Step Workflow Orchestration)
**Status:** Active
**Owner:** CrimsonCrane

## Purpose

Provide a generic saga executor for multi-step remote+local workflows with
deterministic compensating actions. On failure or cancellation, compensations
execute in strict reverse order of successfully completed forward steps,
guaranteeing no partial state.

This bead complements the domain-specific eviction saga (bd-1ru2) by extracting
a reusable, generic pattern that any multi-step workflow can use.

## Core Types

| Type                | Kind   | Description                                        |
|---------------------|--------|----------------------------------------------------|
| `SagaExecutor`      | struct | Manages multiple saga instances and audit log       |
| `SagaInstance`      | struct | Single saga: steps, state, execution records        |
| `SagaStepDef`      | struct | Step definition: name, computation_name, is_remote  |
| `StepOutcome`      | enum   | Success, Failed, Skipped, Compensated               |
| `CompensationTrace`| struct | Exported trace of compensation actions for audit    |
| `SagaState`        | enum   | Pending, Running, Committed, Compensating, Compensated, Failed |
| `StepRecord`       | struct | Record of a single step execution (forward/compensate) |
| `SagaAuditRecord`  | struct | Audit log entry with event code, trace ID, detail   |

## Saga Lifecycle

```
Pending --> Running --> Committed (terminal)
  |           |
  |           +--> Compensating --> Compensated (terminal)
  |                    |
  |                    +--> Failed (terminal, compensation failure)
  +--> Compensating --> Compensated (terminal)
```

### Terminal States

A saga MUST reach one of three terminal states:
- **Committed** -- all forward steps succeeded and saga was committed.
- **Compensated** -- compensations completed; partial state rolled back.
- **Failed** -- a compensation itself failed; requires operator intervention.

## Event Codes

| Code    | Severity | Description                                          |
|---------|----------|------------------------------------------------------|
| SAG-001 | INFO     | Saga instance created and registered                 |
| SAG-002 | INFO     | A forward step executed (success or failure recorded)|
| SAG-003 | INFO     | A compensating action executed for a completed step  |
| SAG-004 | INFO     | All forward steps completed; saga committed          |
| SAG-005 | INFO     | All compensations completed; saga fully rolled back  |
| SAG-006 | ERROR    | A compensation action itself failed                  |
| SAG-007 | INFO     | A forward step was skipped (pre-condition not met)   |
| SAG-008 | INFO     | Compensation trace exported for audit/replay         |

## Invariants

- **INV-SAGA-TERMINAL** -- Every saga eventually reaches a terminal state
  (Committed, Compensated, or Failed). No saga remains in Running or
  Compensating indefinitely.

- **INV-SAGA-REVERSE-COMP** -- Compensations execute in strict reverse order
  of successfully completed forward steps. If steps [0, 1, 2] succeeded,
  compensations run [2, 1, 0].

- **INV-SAGA-IDEMPOTENT-COMP** -- Compensating an already-Compensated saga
  is a no-op. This allows safe retries after transient failures.

- **INV-SAGA-DETERMINISTIC** -- Given the same inputs (step definitions and
  outcomes), the saga executor produces identical compensation traces.
  This supports audit replay and verification.

- **INV-SAGA-AUDITABLE** -- Every state transition is recorded in the audit
  log with an event code, trace ID, saga ID, and structured detail payload.
  The audit log is exportable as JSONL.

## Remote Computation Integration

Steps may reference a remote computation by name via the `computation_name`
field on `SagaStepDef`. When `is_remote` is true, the step is expected to
involve a remote call to the computation registry. An optional `idempotency_key`
supports safe retries of remote calls.

## Compensation Semantics

1. Only steps with `StepOutcome::Success` are compensated.
2. Steps with `StepOutcome::Failed`, `StepOutcome::Skipped`, or
   `StepOutcome::Compensated` are NOT compensated (they either never
   produced side effects or were already rolled back).
3. The `CompensationTrace` records all compensation actions for audit and
   replay purposes.
4. A committed saga cannot be compensated (enforced by state check).

## Audit Trail

The `SagaExecutor` maintains a chronological audit log of `SagaAuditRecord`
entries. Each record contains:
- `event_code`: One of SAG-001 through SAG-008
- `trace_id`: Distributed trace correlation ID
- `saga_id`: The saga this event relates to
- `detail`: Structured JSON payload with event-specific data

The audit log is exportable via `export_audit_log_jsonl()` as newline-delimited
JSON for ingestion by external audit systems.

## Test Requirements

The implementation MUST include at least 15 unit tests covering:
- Saga creation and step definitions
- Sequential step execution
- Full commit path (all steps succeed)
- Compensation in reverse order
- Partial compensation (fail mid-saga)
- Terminal state enforcement
- Idempotent compensation
- Deterministic compensation traces
- Comprehensive trace recording
- Missing saga error handling
- Content hash determinism
- Audit log completeness
- State transition validation
- Remote computation step references
- Multiple concurrent sagas

## Acceptance Criteria

1. `SagaExecutor` supports creating sagas with arbitrary step definitions.
2. Forward steps execute in order; compensations execute in reverse.
3. Committed sagas cannot be compensated; compensated sagas are idempotent.
4. Audit log records every transition with proper event codes.
5. `CompensationTrace` is deterministic and exportable.
6. At least 15 unit tests pass.
7. All 5 invariants are enforced.
8. All 8 event codes are defined and used.
