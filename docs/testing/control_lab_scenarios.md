# Deterministic Lab Runtime Scenarios for Control Protocols

**Bead:** bd-145n | **Section:** 10.15

## Overview

A seed-controlled deterministic lab runtime exercises all high-impact control
protocols. Execution is reproducible: same seed -> same trace -> same result.
Builds on cancellation injection (bd-876n) and virtual transport faults (bd-2qqu)
from Section 10.14.

## Deterministic Lab Runtime Model

- **Seed-controlled scheduler**: All scheduling decisions derive from a PRNG seeded with a fixed u64 value.
- **Test clock**: Time advances only when explicitly ticked, eliminating wall-clock non-determinism.
- **Injected faults**: Cancellation injection and transport faults are deterministically triggered by the seed.
- **Replay guarantee**: Given the same seed, the same scenario produces byte-identical execution traces.

## Scenario Inventory

| Scenario | Protocol | Invariant Asserted |
|---|---|---|
| lab_lifecycle_start_stop | Lifecycle orchestration | Quiescence after stop, no resource leaks |
| lab_rollout_go_abort | Rollout transitions | No half-committed rollout state |
| lab_epoch_commit_abort | Epoch barrier | All participants commit or all abort |
| lab_saga_forward_compensate | Saga compensation | Clean "never happened" after compensate |
| lab_evidence_capture_replay | Evidence capture | Evidence completeness and replay fidelity |

## Per-Scenario Invariants

### lab_lifecycle_start_stop
- All spawned tasks terminate within drain budget.
- No file handles or sockets leak after stop.
- Health gate transitions to unhealthy.

### lab_rollout_go_abort
- Rollout state is either "committed" or "rolled back", never intermediate.
- Peer notifications are idempotent (retry-safe).

### lab_epoch_commit_abort
- All barrier participants in same epoch after completion.
- No split-brain: abort → all remain in epoch N.

### lab_saga_forward_compensate
- Compensation runs in reverse step order.
- Final state equivalent to "never started".

### lab_evidence_capture_replay
- Captured evidence replays with identical hash.
- Evidence chain has no gaps or duplicates.

## Failure Artifact Format

```json
{
  "seed": 42,
  "scenario": "lab_lifecycle_start_stop",
  "invariant_violated": "quiescence_timeout",
  "trace_snapshot": "base64-encoded-trace",
  "timestamp": "2026-02-22T00:00:00Z"
}
```

## Seed Matrix

A set of known-interesting seeds that exercise boundary conditions:
- `0`: zero seed (degenerate case)
- `42`: standard deterministic seed
- `12345`: moderate entropy
- `u64::MAX`: overflow boundary
- `0xDEADBEEF`: common sentinel value
