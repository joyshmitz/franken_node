# Cancellation Protocol Contract (bd-1cs7)

## Overview

Every high-impact control-plane workflow must follow the explicit three-phase
cancellation protocol (REQUEST -> DRAIN -> FINALIZE) rather than abrupt task
termination. This contract defines the protocol semantics, per-workflow cleanup
budgets, timeout behavior, and integration with Cx.

## Three-Phase Protocol

### Phase 1: REQUEST (CAN-001)

Signal intent to cancel. After this phase:
- No new work is accepted (INV-CANP-NO-NEW-WORK).
- Duplicate cancel requests are absorbed without error (INV-CANP-IDEMPOTENT).

### Phase 2: DRAIN (CAN-002, CAN-003, CAN-004)

Complete in-flight work within a bounded budget:
- CAN-002: Drain started.
- CAN-003: Drain completed within budget.
- CAN-004: Drain timeout -- budget exceeded, force-finalize triggered.

### Phase 3: FINALIZE (CAN-005, CAN-006)

Release resources and emit terminal evidence:
- CAN-005: Finalize completed cleanly.
- CAN-006: Resource leak detected post-finalize.

## Per-Workflow Cleanup Budgets

| Workflow | Budget (ms) | Description |
|----------|-------------|-------------|
| lifecycle_shutdown | 5000 | Quiesce health checks, complete in-flight rollout steps, release fencing tokens, close regions |
| rollout_cancel | 3000 | Complete current state transition or roll back, emit terminal state evidence |
| publish_abort | 2000 | Abort in-progress publish, roll back partial writes |
| health_check_cancel | 1000 | Complete current evaluation, emit last-known-good evidence |
| epoch_transition_cancel | 3000 | Abort epoch transition, revert participants to current epoch |

## Timeout Behavior

When drain exceeds the configured budget:
1. CAN-004 is emitted with the actual elapsed time and budget.
2. If `force_on_timeout` is true (default), the protocol transitions to FINALIZE
   with `drain_timed_out = true`.
3. If `force_on_timeout` is false, a `ERR_CANCEL_DRAIN_TIMEOUT` error is returned
   and the protocol remains in the DRAINING state for operator intervention.

Force-finalize always releases resources; it does not silently leak them.

## Integration with Cx

Cancellation signal propagates through `&Cx` to all child operations:
- When a workflow receives REQUEST, it sets the Cx cancellation flag.
- All child operations check the Cx cancellation flag before starting new work.
- Drain handlers receive the Cx reference to coordinate nested cleanup.

## Protocol State Machine

```
IDLE --> CANCEL_REQUESTED --> DRAINING --> DRAIN_COMPLETE --> FINALIZING --> FINALIZED
                |                |                                |
                v                v                                v
            (absorbed)     DRAIN_TIMEOUT --> FINALIZING      LEAK_DETECTED
```

## Invariants

| ID | Statement |
|----|-----------|
| INV-CANP-THREE-PHASE | All cancellations pass through REQUEST, DRAIN, FINALIZE in order |
| INV-CANP-NO-NEW-WORK | After REQUEST, no new operations are accepted |
| INV-CANP-DRAIN-BOUNDED | Drain phase has a configurable timeout; exceeded triggers CAN-004 |
| INV-CANP-FINALIZE-CLEAN | After FINALIZE, no resource leaks exist (CAN-006 on violation) |
| INV-CANP-IDEMPOTENT | Duplicate cancel requests are absorbed without error |
| INV-CANP-AUDIT-COMPLETE | Every phase transition emits a structured audit event |

## Event Codes

| Code | Description |
|------|-------------|
| CAN-001 | Cancel requested |
| CAN-002 | Drain started |
| CAN-003 | Drain completed |
| CAN-004 | Drain timeout -- force finalize |
| CAN-005 | Finalize completed |
| CAN-006 | Resource leak detected |

## Error Codes

| Code | Description |
|------|-------------|
| ERR_CANCEL_INVALID_PHASE | Phase transition not allowed from current state |
| ERR_CANCEL_ALREADY_FINAL | Cancellation attempted on already-finalized workflow |
| ERR_CANCEL_DRAIN_TIMEOUT | Drain exceeded configured timeout |
| ERR_CANCEL_LEAK | Resources leaked during finalization |
