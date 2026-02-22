# bd-2ko: Deterministic Lab Runtime for Control-Plane Protocol Testing

## Purpose

Provide a deterministic lab runtime module that enables fault injection and
replay for all critical control-plane protocol tests. The runtime replaces
wall-clock time with a seed-driven virtual clock, applies faults through a
virtual transport layer, and exposes a scenario builder API so that every
protocol test can be reproduced bit-for-bit from a recorded seed.

## Section

10.11

## Status

Implemented

## Dependencies

- **Upstream:** bd-2qqu (virtual transport fault harness), bd-145n (lab runtime scenarios)
- **Downstream:** any control-plane protocol test that requires deterministic replay

## Contract Summary

The lab runtime module provides deterministic fault injection and replay for all
critical control-plane protocol tests. Tests execute under a virtual clock
seeded from a deterministic PRNG, faults are injected through a virtual
transport layer that intercepts all message sends and receives, and the scenario
builder composes multi-step protocol interactions into reproducible test plans.
When a test fails, the runtime exports a repro bundle containing the seed,
fault schedule, and message trace so the failure can be replayed without
external dependencies.

## Interface Boundary

- **Module:** `testing` (lab_runtime, virtual_transport, scenario_builder)
- **Crate path:** `crates/franken-node/src/testing/`

### Key Types

#### `LabRuntime`

Deterministic test runtime providing:
- `seed` -- PRNG seed for reproducible execution
- `virtual_clock` -- monotonic virtual timer replacing wall-clock
- `fault_schedule` -- ordered list of fault injection points
- `message_log` -- full message trace for replay

#### `VirtualTransport`

Transport shim that intercepts message sends and receives:
- fault injection (drop, delay, duplicate, reorder)
- deterministic delivery ordering
- message trace capture

#### `ScenarioBuilder`

Composable test plan construction:
- step sequencing with named checkpoints
- fault injection declaration
- assertion hooks at each checkpoint
- repro bundle export on failure

## Event Codes

| Code | Event |
|------|-------|
| `FN-LB-001` | `LAB_RUNTIME_INIT` |
| `FN-LB-002` | `LAB_RUNTIME_SEED_SET` |
| `FN-LB-003` | `LAB_RUNTIME_SCENARIO_START` |
| `FN-LB-004` | `LAB_RUNTIME_SCENARIO_COMPLETE` |
| `FN-LB-005` | `LAB_TRANSPORT_FAULT_INJECTED` |
| `FN-LB-006` | `LAB_TRANSPORT_MESSAGE_DELIVERED` |
| `FN-LB-007` | `LAB_TRANSPORT_MESSAGE_DROPPED` |
| `FN-LB-008` | `LAB_REPLAY_START` |
| `FN-LB-009` | `LAB_REPLAY_COMPLETE` |
| `FN-LB-010` | `LAB_REPRO_BUNDLE_EXPORTED` |

## Invariants

| ID | Description |
|----|-------------|
| `INV-LB-DETERMINISTIC` | Given the same seed and fault schedule, the lab runtime produces identical message traces across runs |
| `INV-LB-TIMER-ORDER` | Virtual clock events are delivered in strict monotonic order; no timer inversion is possible |
| `INV-LB-FAULT-APPLIED` | Every fault in the fault schedule is applied exactly once at the declared injection point |
| `INV-LB-REPLAY` | A repro bundle replays the original execution with bit-identical message ordering and fault timing |
| `INV-LB-COVERAGE` | Every control-plane protocol path exercised in scenarios is recorded in the coverage map |
| `INV-LB-NO-WALLCLOCK` | The lab runtime never reads wall-clock time; all timing derives from the virtual clock |

## Acceptance Criteria

1. The lab runtime initializes from a deterministic seed and produces identical
   message traces when re-run with the same seed and fault schedule.
2. The virtual transport layer injects faults (drop, delay, duplicate, reorder)
   at declared injection points and logs every delivery or drop.
3. The scenario builder composes multi-step protocol interactions with named
   checkpoints and assertion hooks.
4. DPOR exploration covers at least 128 interleavings per scenario without
   finding ordering-dependent failures.
5. On test failure, the runtime exports a repro bundle containing the seed,
   fault schedule, and full message trace.
6. No wall-clock reads occur inside the lab runtime; all timing is virtual.
7. The gate script `scripts/check_deterministic_lab.py` passes all checks.

## Artifacts

- Implementation: `crates/franken-node/src/testing/lab_runtime.rs`
- Virtual transport: `crates/franken-node/src/testing/virtual_transport.rs`
- Scenario builder: `crates/franken-node/src/testing/scenario_builder.rs`
- Verification script: `scripts/check_deterministic_lab.py`
- Evidence: `artifacts/section_10_11/bd-2ko/verification_evidence.json`
- Summary: `artifacts/section_10_11/bd-2ko/verification_summary.md`
