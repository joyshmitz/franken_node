# Canonical Virtual Transport Fault Harness for Distributed Control Protocols

**Bead:** bd-3u6o | **Section:** 10.15

## Overview

This document defines how the canonical virtual transport fault harness (bd-2qqu,
Section 10.14) is enforced across all distributed control protocols in
franken_node. Every protocol that exchanges messages between nodes or across
trust boundaries must be exercised under deterministic fault injection using
the shared `VirtualTransportFaultHarness` from
`crates/franken-node/src/remote/virtual_transport_faults.rs`. No protocol may
ship a custom or ad-hoc fault harness.

## Protocols Tested

| Protocol | Module | Description |
|----------|--------|-------------|
| Remote Fencing | `connector/fencing.rs` | Distributed lock acquisition, release, and fencing token validation across nodes |
| Cross-Node Rollout | `connector/rollout_state.rs` | Coordinated state transitions replicated to peer nodes during progressive rollout |
| Epoch Barrier Participation | `control_plane/epoch_transition_barrier.rs` | Barrier-based epoch transitions requiring unanimous commit or abort across participants |
| Distributed Saga Steps | `control_plane/transition_abort.rs` | Multi-step distributed sagas with forward execution and compensating rollback |

## Fault Classes

All four canonical fault classes from the upstream harness (bd-2qqu) apply:

| Fault Class | Effect | Transport Behavior |
|-------------|--------|--------------------|
| **DROP** | Message is silently discarded | Simulates network loss, firewall drop, or timeout |
| **REORDER** | Messages arrive out of send order | Simulates out-of-order delivery, path asymmetry |
| **CORRUPT** | Bit-level corruption of message payload | Simulates bit-rot, truncation, or partial write |
| **PARTITION** | Bidirectional communication blackout between node subsets | Simulates network partition, split-brain |

## Deterministic Seed Model

The fault harness uses a seed-controlled PRNG to produce reproducible fault
sequences.

### Properties

- **Same seed produces the same fault sequence**: Given identical seed, protocol,
  and message count, the exact same faults fire at the exact same positions.
- **Seed space**: u64 (0 through 2^64 - 1).
- **Known-interesting seeds**: 0 (degenerate), 42 (standard), 12345 (moderate
  entropy), 3735928559 / 0xDEADBEEF (sentinel), 18446744073709551615 / u64::MAX
  (overflow boundary).
- **Replay guarantee**: Replaying a scenario with the same seed produces
  byte-identical fault logs and protocol outcomes.

### Seed Matrix

Each protocol is tested with all 5 known-interesting seeds. The total test
matrix is 4 protocols x 5 seeds = 20 test executions.

| Seed | Remote Fencing | Cross-Node Rollout | Epoch Barrier | Distributed Saga |
|------|----------------|--------------------|---------------|------------------|
| 0 | retry/succeed | retry/succeed | commit | forward/complete |
| 42 | retry/succeed | abort/rollback | commit | forward/complete |
| 12345 | fail-closed | retry/succeed | abort | compensate |
| 0xDEADBEEF | retry/succeed | retry/succeed | commit | forward/complete |
| u64::MAX | fail-closed | abort/rollback | abort | compensate |

## Expected Behaviors Under Faults

### Remote Fencing
- **DROP**: Fencing acquire retries up to 3 times, then fails closed (no lock granted).
- **REORDER**: Fencing tokens include monotonic sequence numbers; out-of-order tokens are rejected.
- **CORRUPT**: Integrity check on fencing token detects corruption; request is rejected.
- **PARTITION**: Fencing lease expires; node assumes fence is lost and fails closed.

### Cross-Node Rollout
- **DROP**: Rollout coordinator retries notification; if all retries exhausted, rollout aborts.
- **REORDER**: Rollout steps carry causal ordering metadata; out-of-order steps are re-sequenced.
- **CORRUPT**: Rollout state hash mismatch triggers rollback to last known-good state.
- **PARTITION**: Partitioned nodes cannot confirm rollout; coordinator aborts after timeout.

### Epoch Barrier Participation
- **DROP**: Barrier vote is retried; if quorum is not reached within timeout, epoch aborts.
- **REORDER**: Votes carry epoch and round identifiers; stale votes are discarded.
- **CORRUPT**: Vote integrity check fails; corrupted vote is treated as abstention.
- **PARTITION**: Partitioned participants cannot vote; barrier aborts (no split-brain).

### Distributed Saga Steps
- **DROP**: Saga coordinator retries step delivery; if step is lost permanently, compensate.
- **REORDER**: Steps carry sequence numbers; out-of-order delivery triggers re-sequencing.
- **CORRUPT**: Step payload hash mismatch triggers step rejection and compensation.
- **PARTITION**: Unreachable participants trigger saga compensation in reverse order.

## Invariants

| Invariant | Description |
|-----------|-------------|
| **INV-VTF-DETERMINISTIC** | Same seed and protocol produce identical fault sequences and protocol outcomes across runs |
| **INV-VTF-CORRECT-OR-FAIL** | Under any fault combination, each protocol either produces a correct result or cleanly fails; no silent corruption or inconsistent state is permitted |
| **INV-VTF-NO-CUSTOM** | No protocol may implement its own fault injection; all must use the canonical `VirtualTransportFaultHarness` from bd-2qqu |
| **INV-VTF-SEED-STABLE** | The mapping from seed to fault schedule does not change across code versions; a seed that caused a failure in version N must cause the same failure in version N+1 unless the bug is intentionally fixed |

## Event Codes

| Code | Event | Description |
|------|-------|-------------|
| **VTF-001** | Fault schedule created | Deterministic schedule generated from seed, fault class, and message count |
| **VTF-002** | Fault injected | A fault was applied to a protocol message during transport |
| **VTF-003** | Protocol outcome recorded | Protocol completed with outcome `correct_completion` or `deterministic_failure` |
| **VTF-004** | Seed determinism verified | Replay with same seed produced identical fault log and protocol outcome |
| **VTF-005** | Campaign summary emitted | Full fault campaign completed; summary with pass/fail counts emitted |

## Upstream Dependency

This bead adopts the harness defined in:
- **bd-2qqu** (Section 10.14): `crates/franken-node/src/remote/virtual_transport_faults.rs`
- Types reused: `VirtualTransportFaultHarness`, `FaultClass`, `FaultConfig`, `FaultSchedule`
- The PARTITION fault class extends the base harness's DROP/REORDER/CORRUPT set by
  applying bidirectional DROP between disjoint node subsets.

## Acceptance Criteria

1. All 4 protocols are exercised under all 4 fault classes.
2. All 20 seed-protocol combinations (4 protocols x 5 seeds) pass.
3. No protocol uses a custom fault harness; all reference `VirtualTransportFaultHarness`.
4. Fault logs are reproducible given the same seed.
5. Every protocol either succeeds correctly or fails closed under faults.
