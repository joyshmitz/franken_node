# DPOR-Style Schedule Exploration Scope for Control-Plane Interactions

**Bead:** bd-25oa | **Section:** 10.15

## Overview

This document defines the scope for enforcing canonical DPOR (Dynamic Partial
Order Reduction) schedule exploration on control-plane protocol interactions.
The DPOR explorer (bd-22yy, Section 10.14) provides the exploration engine;
this bead enforces its adoption across four protocol interaction classes that
govern epoch, lease, remote-computation, and evidence lifecycles.

Every interaction class is modelled as a set of concurrent operations with
explicit dependency edges. The DPOR explorer enumerates valid interleavings,
prunes equivalent schedules, and checks safety invariants at each explored
state.

## Protocol Interaction Classes

### 1. epoch_transition + lease_renewal

Concurrent epoch transitions and lease renewals interact through shared fencing
tokens. The model captures:

| Operation | Actor | Dependencies |
|-----------|-------|-------------|
| propose_epoch | epoch_leader | -- |
| drain_services | svc_pool | propose_epoch |
| commit_epoch | epoch_leader | drain_services |
| request_lease | lease_client | -- |
| validate_lease_epoch | lease_server | request_lease |
| grant_lease | lease_server | validate_lease_epoch, commit_epoch |

**Safety properties:**
- No lease granted for a stale epoch (epoch has advanced past the lease epoch).
- No split-brain epochs: at most one epoch is active at any point.
- Lease renewal does not block epoch commit indefinitely.

### 2. remote_computation + evidence_emission

Remote capability acquisition, execution, and release interleave with evidence
emission and archival. The model captures:

| Operation | Actor | Dependencies |
|-----------|-------|-------------|
| acquire_capability | remote_client | -- |
| execute_remote | remote_client | acquire_capability |
| emit_evidence | evidence_emitter | execute_remote |
| release_capability | remote_client | emit_evidence |
| archive_evidence | evidence_archiver | emit_evidence |
| epoch_checkpoint | epoch_leader | -- |

**Safety properties:**
- No orphaned evidence: every emitted evidence record is archived or explicitly
  discarded.
- No execution without a valid capability.
- Evidence emission precedes capability release.

### 3. cancellation + saga_compensation

Cancellation injection at any await point must trigger saga compensation in
reverse order. The model captures:

| Operation | Actor | Dependencies |
|-----------|-------|-------------|
| saga_step_1 | orchestrator | -- |
| saga_step_2 | orchestrator | saga_step_1 |
| saga_step_3 | orchestrator | saga_step_2 |
| cancel_inject | cancellation_framework | -- |
| compensate_3 | orchestrator | cancel_inject, saga_step_3 |
| compensate_2 | orchestrator | compensate_3 |
| compensate_1 | orchestrator | compensate_2 |

**Safety properties:**
- No leaked obligations: all committed saga steps are compensated.
- Compensation runs in reverse order (3 -> 2 -> 1).
- Final state equivalent to "never started".

### 4. epoch_barrier + fencing_token

Epoch barriers coordinate multi-participant transitions. Fencing tokens prevent
stale writes. The model captures:

| Operation | Actor | Dependencies |
|-----------|-------|-------------|
| issue_fence | fence_authority | -- |
| barrier_propose | epoch_leader | -- |
| barrier_drain_a | svc_a | barrier_propose |
| barrier_drain_b | svc_b | barrier_propose |
| barrier_commit | epoch_leader | barrier_drain_a, barrier_drain_b |
| write_with_fence | writer | issue_fence |
| validate_fence | fence_authority | write_with_fence, barrier_commit |

**Safety properties:**
- No stale writes accepted after epoch barrier commits with a newer fence.
- Fencing token validation rejects tokens from previous epochs.
- Barrier commit requires all participants to drain.

## DPOR Exploration Budget

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| max_interleavings_per_class | 10000 | Bounded CI wall-clock time |
| total_budget_per_ci_run | 40000 | 4 classes x 10000 |
| time_budget_per_class_sec | 120 | 2 minutes per class |
| memory_budget_bytes | 1073741824 | 1 GB per class |

The budget is enforced by the DPOR explorer's `ExplorationBudget` type. If the
budget is exceeded, the exploration reports partial coverage and the gate
degrades to a warning rather than a hard failure, provided at least 80% of
estimated schedules were explored.

## Invariant Assertions

| Invariant ID | Rule |
|-------------|------|
| INV-DPOR-BOUNDED | Exploration respects the CI time and memory budgets defined above |
| INV-DPOR-INVARIANT-CHECK | Safety properties are checked at every explored state for every interaction class |
| INV-DPOR-COUNTEREXAMPLE | Any violation produces a minimal interleaving trace (counterexample) |
| INV-DPOR-CANONICAL | All interaction classes use the canonical DporExplorer from bd-22yy; no custom exploration logic |

### Interaction-class-specific invariants

| Invariant ID | Class | Rule |
|-------------|-------|------|
| INV-DPOR-NO-SPLIT-BRAIN | epoch_transition+lease_renewal | At most one active epoch at any state |
| INV-DPOR-NO-ORPHANED-LEASE | epoch_transition+lease_renewal | No lease outlives its granting epoch |
| INV-DPOR-NO-LEAKED-OBLIGATIONS | cancellation+saga_compensation | All committed steps compensated on cancel |
| INV-DPOR-NO-INCONSISTENT-EVIDENCE | remote_computation+evidence_emission | Evidence consistent with execution outcome |
| INV-DPOR-NO-STALE-WRITE | epoch_barrier+fencing_token | No write accepted with an outdated fence |

## Counterexample Format

When a safety violation is found, the DPOR explorer emits a minimal
counterexample trace:

```json
{
  "model_name": "epoch_transition_lease_renewal",
  "violated_property": "no_split_brain",
  "length": 4,
  "steps": [
    {
      "step_index": 0,
      "operation_id": "propose_epoch",
      "actor": "epoch_leader",
      "state_summary": "epoch=1, leases=[]"
    },
    {
      "step_index": 1,
      "operation_id": "request_lease",
      "actor": "lease_client",
      "state_summary": "epoch=1, pending_lease=true"
    },
    {
      "step_index": 2,
      "operation_id": "commit_epoch",
      "actor": "epoch_leader",
      "state_summary": "epoch=2, leases=[]"
    },
    {
      "step_index": 3,
      "operation_id": "grant_lease",
      "actor": "lease_server",
      "state_summary": "epoch=2, lease_epoch=1 (STALE)"
    }
  ]
}
```

The counterexample is:
- **Minimal**: the shortest interleaving that triggers the violation.
- **Reproducible**: the same model and seed produce the same counterexample.
- **Structured**: uses the `Counterexample` / `CounterexampleStep` types from
  `dpor_exploration.rs`.

## Upstream Dependency

This document adopts the DPOR exploration engine implemented in:

- `crates/franken-node/src/control_plane/dpor_exploration.rs` (bd-22yy, Section 10.14)

The explorer provides: `DporExplorer`, `ProtocolModel`, `Operation`,
`SafetyProperty`, `Counterexample`, `CounterexampleStep`, `ExplorationBudget`,
`ExplorationResult`.

## Event Codes

| Code | Description |
|------|-------------|
| DPR-001 | DPOR scope document validated: all protocol interaction classes, budget, and invariants are present |
| DPR-002 | Exploration summary report validated: bead, section, interaction classes, and summary match |
| DPR-003 | Interaction class coverage confirmed: all 4 classes documented in scope doc and report |
| DPR-004 | Upstream DPOR explorer verified: file exists with required types (DporExplorer, ProtocolModel, etc.) |
| DPR-005 | Gate verdict emitted: exploration passed with zero invariant violations across all classes |

## Rust Exploration Test

A self-contained Rust test file at `tests/lab/control_dpor_exploration.rs`
models DPOR exploration for all four interaction classes. The file uses
bounded-budget simulation (no external dependencies beyond `serde`, `sha2`)
and verifies:

- Each class produces zero violations under bounded exploration.
- Budget limits are respected.
- Counterexamples are generated when invariants are deliberately broken.
- State hashing produces deterministic fingerprints.

## CI Integration

The DPOR exploration gate is checked by:

- `scripts/check_control_dpor_scope.py` -- verifies this document, the summary
  report, the Rust test file, and the upstream explorer exist and are consistent.
- `tests/test_check_control_dpor_scope.py` -- unit tests for the gate script.
