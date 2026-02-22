# bd-25oa: Enforce Canonical DPOR-Style Schedule Exploration for Control-Plane Interactions

**Section:** 10.15 | **Type:** task (adoption/integration) | **Priority:** P1

## Overview

Enforces the canonical DPOR (Dynamic Partial Order Reduction) schedule
exploration engine (bd-22yy, Section 10.14) across four critical control-plane
interaction classes:

1. epoch_transition + lease_renewal
2. remote_computation + evidence_emission
3. cancellation + saga_compensation
4. epoch_barrier + fencing_token

This is an adoption bead: it documents the scope, budget, invariants, and
counterexample format for DPOR exploration of control-plane protocols. The
upstream DPOR explorer (`dpor_exploration.rs`) provides the engine; this bead
defines *what* is explored and *how much*.

## Invariants

| ID | Rule |
|----|------|
| INV-DPOR-BOUNDED | Exploration respects CI time (120s/class) and memory (1GB) budgets |
| INV-DPOR-INVARIANT-CHECK | Safety properties checked at every explored state for all 4 classes |
| INV-DPOR-COUNTEREXAMPLE | Any violation produces a minimal interleaving trace |
| INV-DPOR-CANONICAL | All classes use the canonical DporExplorer; no custom exploration logic |

## Interaction Classes (4)

| Class | Operations | Safety Properties |
|-------|-----------|-------------------|
| epoch_transition+lease_renewal | 6 | no_split_brain, no_stale_lease, no_deadlock |
| remote_computation+evidence_emission | 6 | no_orphaned_evidence, no_exec_without_cap, evidence_before_release |
| cancellation+saga_compensation | 7 | no_leaked_obligations, reverse_order, clean_state |
| epoch_barrier+fencing_token | 7 | no_stale_write, fence_epoch_match, all_drain_before_commit |

## Exploration Budget

- max_interleavings_per_class: 10000
- total_budget_per_ci_run: 40000 (4 classes x 10000)
- time_budget_per_class: 120 seconds
- memory_budget: 1 GB per class

## Counterexample Format

Minimal interleaving trace using `Counterexample` and `CounterexampleStep`
types from `dpor_exploration.rs`. Fields: model_name, violated_property,
length, steps[].{step_index, operation_id, actor, state_summary}.

## Upstream Dependency

- bd-22yy (Section 10.14): `crates/franken-node/src/control_plane/dpor_exploration.rs`

## Event Codes

| Code | Description |
|------|-------------|
| DPR-001 | DPOR scope document validated |
| DPR-002 | Exploration summary report validated |
| DPR-003 | Interaction class coverage confirmed |
| DPR-004 | Upstream explorer verified |
| DPR-005 | Gate verdict emitted |
| CDP-001 | DPOR scope document validated |
| CDP-002 | Exploration summary report validated |
| CDP-003 | Interaction class coverage confirmed |
| CDP-004 | Upstream explorer verified |
| CDP-005 | Budget constraints documented |
| CDP-006 | Invariant assertions documented |
| CDP-007 | Counterexample format documented |
| CDP-008 | Gate verdict emitted |

## Acceptance Criteria

- Scope document exists at `docs/testing/control_dpor_scope.md`
- Summary report exists at `artifacts/10.15/control_dpor_exploration_summary.json`
- All 4 interaction classes are documented with operations and safety properties
- DPOR exploration budget is defined with per-class and total limits
- Counterexample format is documented and matches upstream types
- Upstream DPOR explorer file exists and contains required types
- Invariants INV-DPOR-BOUNDED, INV-DPOR-INVARIANT-CHECK, INV-DPOR-COUNTEREXAMPLE, INV-DPOR-CANONICAL are documented
- Verification gate passes with zero failures

## Artifacts

- `docs/testing/control_dpor_scope.md`
- `docs/specs/section_10_15/bd-25oa_contract.md`
- `tests/lab/control_dpor_exploration.rs`
- `artifacts/10.15/control_dpor_results.json`
- `artifacts/10.15/control_dpor_exploration_summary.json`
- `scripts/check_control_dpor_scope.py`
- `tests/test_check_control_dpor_scope.py`
- `artifacts/section_10_15/bd-25oa/verification_evidence.json`
- `artifacts/section_10_15/bd-25oa/verification_summary.md`
