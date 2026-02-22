# bd-7om: Canonical Cancel -> Drain -> Finalize Protocol Contracts for Product Services

---
schema_version: cxt-v1.0
bead_id: bd-7om
section: "10.11"
---

## Summary

Adopts the canonical cancel -> drain -> finalize protocol contracts from section
10.15 (bd-1cs7) for product services. Implements a `CancellableTask` trait and
`CancellationRuntime` that manage the three-phase lifecycle for all long-running
product operations. Every cancellable task passes through cancel, drain, and
finalize in strict order, producing an auditable `FinalizeRecord` with obligation
closure proof at the end.

## Scope

- `CancellableTask` trait with `on_cancel`, `on_drain_complete`, `on_finalize`
- `CancellationRuntime` struct managing registered tasks through the lifecycle
- `DrainResult` enum (Completed, TimedOut, Error)
- `FinalizeRecord` with full phase timestamps and obligation closure proof
- `ObligationClosureProof` covering all registered obligations
- Nested/child task cancel propagation
- Lane slot release tracking after finalization

## Invariants

| ID | Statement |
|----|-----------|
| INV-CXT-THREE-PHASE | All tasks pass through cancel, drain, finalize in order |
| INV-CXT-DRAIN-BOUNDED | Drain has a finite, configurable timeout |
| INV-CXT-FINALIZE-RECORD | Every finalization produces a signed FinalizeRecord |
| INV-CXT-CLOSURE-COMPLETE | Obligation closure proof covers all registered obligations |
| INV-CXT-LANE-RELEASE | Lane slot is released only after finalization completes |
| INV-CXT-NESTED-PROPAGATION | Cancel propagates to nested/child tasks |

## Event Codes

| Code | Description |
|------|-------------|
| FN-CX-001 | Task registered with CancellationRuntime |
| FN-CX-002 | Cancel signal sent to task |
| FN-CX-003 | Drain phase started |
| FN-CX-004 | Drain phase completed successfully |
| FN-CX-005 | Drain phase timed out |
| FN-CX-006 | Finalize phase started |
| FN-CX-007 | FinalizeRecord produced |
| FN-CX-008 | Lane slot released after finalization |
| FN-CX-009 | Nested cancel propagated to child |
| FN-CX-010 | Obligation closure incomplete |

## Error Codes

| Code | Description |
|------|-------------|
| ERR_CXT_INVALID_PHASE | Phase transition not allowed from current state |
| ERR_CXT_DRAIN_TIMEOUT | Drain exceeded configured timeout |
| ERR_CXT_CLOSURE_INCOMPLETE | Obligation closure proof missing entries |
| ERR_CXT_TASK_NOT_FOUND | Task not found in the runtime |
| ERR_CXT_ALREADY_FINALIZED | Task already in terminal state |
| ERR_CXT_DUPLICATE_TASK | Duplicate task registration |

## Acceptance Criteria

1. `CancellableTask` trait exists with `on_cancel`, `on_drain_complete`, `on_finalize`
2. `CancellationRuntime` manages registered tasks through cancel -> drain -> finalize
3. `DrainResult` enum covers Completed, TimedOut, Error
4. `FinalizeRecord` includes task_id, cancel_reason, drain_status, obligation_closure_proof, phase timestamps
5. `ObligationClosureProof` with obligation IDs and terminal states
6. `register_task` and `cancel_task` public API on `CancellationRuntime`
7. Drain timeout detection with configurable budget
8. Nested cancel propagation to child tasks
9. Lane slot release event after finalization
10. All 10 event codes emitted at correct phase boundaries
11. All 6 error codes mapped to error variants
12. All 6 invariant constants defined
13. Schema version `cxt-v1.0`
14. At least 15 unit tests in `#[cfg(test)]` module
15. Gate script passes all checks

## Dependencies

- **Upstream**: bd-1cs7 (three-phase cancellation protocol, 10.15)
- **Upstream**: bd-qlc6 (lane-aware scheduler, 10.11)
- **Upstream**: bd-lus (global bulkhead, 10.11)

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_11/bd-7om_contract.md` |
| Implementation | `crates/franken-node/src/runtime/cancellable_task.rs` |
| Gate script | `scripts/check_cancellable_task_protocol.py` |
| Python tests | `tests/test_check_cancellable_task_protocol.py` |
| Verification evidence | `artifacts/section_10_11/bd-7om/verification_evidence.json` |
| Verification summary | `artifacts/section_10_11/bd-7om/verification_summary.md` |
