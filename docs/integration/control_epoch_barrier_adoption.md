# Control-Plane Epoch Barrier Adoption

**Bead:** bd-1hbw | **Section:** 10.15

## Overview

This document defines how the canonical epoch transition barrier protocol
(bd-2wsm, Section 10.14) is integrated into the control-plane layer. All
control services participate in epoch barriers with deterministic
arrival/drain/commit/abort semantics.

## Barrier Participants

| Participant ID | Module | Role |
|---|---|---|
| connector_lifecycle | `connector/lifecycle.rs` | Drains in-flight lifecycle operations |
| rollout_engine | `connector/rollout_state.rs` | Drains in-flight rollout transitions |
| fencing_service | `connector/fencing.rs` | Drains fencing token operations |
| health_gate | `connector/health_gate.rs` | Pauses health checks during transition |

## Arrival/Drain/Commit Protocol

1. **Barrier proposed**: The epoch coordinator proposes transition from epoch N to N+1.
2. **Participant arrival**: Each participant signals arrival at the barrier.
3. **Drain phase**: Each participant drains in-flight epoch-N work within its budget.
4. **Drain ACK**: Each participant acknowledges drain completion.
5. **Commit**: When all participants have ACKed drain, the barrier commits to epoch N+1.

## Abort Semantics

- **Timeout abort**: If any participant fails to arrive within `DEFAULT_BARRIER_TIMEOUT_MS`, the barrier aborts. All participants remain in epoch N.
- **Cancel abort**: If cancellation is requested during a barrier, the barrier aborts deterministically. No participant transitions.
- **Drain failure abort**: If any participant fails to drain, the barrier aborts.
- **Atomic guarantee**: Either ALL participants commit to epoch N+1, or ALL remain in epoch N. No split-brain.

## Prohibition on Custom Barriers

No module under `crates/franken-node/src/connector/` may implement its own
barrier protocol. All epoch transitions go through the canonical
`EpochTransitionBarrier` from Section 10.14.

## Error Handling

| Error Code | Trigger | Recovery |
|---|---|---|
| `ERR_BARRIER_TIMEOUT` | Participant arrival timeout | Abort, remain epoch N |
| `ERR_BARRIER_DRAIN_FAILED` | Participant drain failure | Abort, remain epoch N |
| `ERR_BARRIER_CONCURRENT` | Concurrent barrier attempt | Reject second barrier |
| `ERR_BARRIER_EPOCH_MISMATCH` | Non-sequential epoch transition | Reject proposal |

## Invariants

| ID | Rule |
|----|------|
| INV-EPB-CANONICAL | Product layer uses canonical 10.14 barrier protocol |
| INV-EPB-ALL-ARRIVE | All participants must arrive before commit |
| INV-EPB-NO-SPLIT-BRAIN | Abort leaves all in previous epoch |
| INV-EPB-DETERMINISTIC-ABORT | Cancel/timeout abort is deterministic |
| INV-EPB-TRANSCRIPT-STABLE | Barrier transcript is replay-stable |

## Structured Log Events

| Code | Description |
|------|-------------|
| EPB-001 | Barrier opened |
| EPB-002 | Participant arrived |
| EPB-003 | Participant drained |
| EPB-004 | Barrier committed (epoch N+1) |
| EPB-005 | Barrier aborted (remain epoch N) |
| EPB-006 | Participant timeout |
