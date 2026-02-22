# bd-25oa Verification Summary

## Result
PASS

## Delivered
- `docs/testing/control_dpor_scope.md`
- `docs/specs/section_10_15/bd-25oa_contract.md`
- `tests/lab/control_dpor_exploration.rs`
- `artifacts/10.15/control_dpor_results.json`
- `artifacts/10.15/control_dpor_exploration_summary.json`
- `scripts/check_control_dpor_scope.py`
- `tests/test_check_control_dpor_scope.py`
- `artifacts/section_10_15/bd-25oa/verification_evidence.json`
- `artifacts/section_10_15/bd-25oa/verification_summary.md`

## Commands
- `python3 scripts/check_control_dpor_scope.py --json`
- `python3 scripts/check_control_dpor_scope.py --self-test`
- `python3 -m pytest tests/test_check_control_dpor_scope.py -v`

## Key Outcomes

| Metric | Value |
|--------|-------|
| Python gate checks | 106/106 |
| Python unit tests | 65/65 |
| Rust test count | 19 |
| Interaction classes | 4 |
| Invariants documented | 9 (INV-DPOR-*) |
| DPR event codes | 5 (DPR-001..DPR-005) |
| CDP event codes | 8 (CDP-001..CDP-008) |
| Upstream types verified | 8 |
| Schema version | cdpor-v1.0 |

## Interaction Classes

1. **epoch_transition + lease_renewal** (6 ops, 3 safety props)
   - no_split_brain, no_stale_lease, no_deadlock
2. **remote_computation + evidence_emission** (6 ops, 3 safety props)
   - no_orphaned_evidence, no_exec_without_cap, evidence_before_release
3. **cancellation + saga_compensation** (7 ops, 3 safety props)
   - no_leaked_obligations, reverse_compensation_order, clean_final_state
4. **epoch_barrier + fencing_token** (7 ops, 3 safety props)
   - no_stale_write, fence_epoch_match, all_drain_before_commit

## DPOR Exploration Budget

- max_interleavings_per_class: 10,000
- total_budget_per_ci_run: 40,000
- time_budget_per_class: 120 seconds
- memory_budget: 1 GB per class

## Rust Test File

`tests/lab/control_dpor_exploration.rs` models DPOR exploration for all 4
interaction classes with 19 tests covering:

- Operation count and invariant count per class
- Zero violations under bounded exploration
- Budget limit enforcement
- Deterministic state fingerprinting
- Counterexample generation on broken invariants
- Serialization round-trip
- All-class exploration pass

## Invariants

- INV-DPOR-BOUNDED: Exploration respects CI time and memory budgets
- INV-DPOR-INVARIANT-CHECK: Safety properties checked at every explored state
- INV-DPOR-COUNTEREXAMPLE: Violations produce minimal counterexample traces
- INV-DPOR-CANONICAL: All classes use canonical DporExplorer from bd-22yy
- INV-DPOR-NO-SPLIT-BRAIN: At most one active epoch at any state
- INV-DPOR-NO-ORPHANED-LEASE: No lease outlives its granting epoch
- INV-DPOR-NO-LEAKED-OBLIGATIONS: All committed steps compensated on cancel
- INV-DPOR-NO-INCONSISTENT-EVIDENCE: Evidence consistent with execution outcome
- INV-DPOR-NO-STALE-WRITE: No write accepted with outdated fence

## Upstream Dependency

bd-22yy (Section 10.14): `crates/franken-node/src/control_plane/dpor_exploration.rs`
