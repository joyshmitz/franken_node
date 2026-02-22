# bd-2tdi: Region-Owned Execution Trees

---
schema_version: region-v1.0
bead_id: bd-2tdi
section: 10.15
---

## Summary

Migrates lifecycle and rollout orchestration from ad-hoc task coordination to a
structured region-owned execution tree. Each region owns a subtree of tasks and
enforces quiescence guarantees: a region cannot close until all descendant tasks
have drained or been force-terminated within a configurable budget.

## Region Hierarchy

```
ConnectorLifecycle (root, 5000ms budget)
├── HealthGate (2000ms budget)
├── Rollout (2000ms budget)
└── Fencing (2000ms budget)
```

| Region | Kind | Parent | Purpose |
|--------|------|--------|---------|
| root | ConnectorLifecycle | (none) | Top-level orchestrator region |
| health | HealthGate | root | Health-check probes and readiness gates |
| rollout | Rollout | root | Rolling update state transitions |
| fencing | Fencing | root | Distributed fencing token acquisition |

## Ownership Rules

1. **Single parent**: Every region except root has exactly one parent region.
2. **No re-parenting**: Once a region is created under a parent, it cannot be moved.
3. **Task scoping**: Tasks registered to a region are owned by that region; they
   cannot outlive the region.
4. **Close is idempotent barrier**: `close()` drains tasks within budget,
   force-terminates stragglers, and rejects further task registration.
5. **Double close rejected**: Calling `close()` on a closed region returns
   `RegionError::AlreadyClosed`.

## Quiescence Guarantees

| Level | Guarantee |
|-------|-----------|
| Leaf region (no children) | All registered tasks complete or are force-terminated within budget |
| Interior region | All child regions reach quiescence, then own tasks drain |
| Root | Full tree quiescence before returning from close() |

## Invariants

| ID | Statement |
|----|-----------|
| INV-RGN-QUIESCENCE | A region's close() blocks until all tasks reach quiescence or budget expires |
| INV-RGN-NO-OUTLIVE | No task registered to a region may outlive that region's Closed state |
| INV-RGN-HIERARCHY | Parent-child relationships are immutable after creation |
| INV-RGN-DETERMINISTIC | Quiescence traces are reproducible given the same input |

## Event Codes

| Code | Description |
|------|-------------|
| RGN-001 | Region opened |
| RGN-002 | Region close initiated |
| RGN-003 | Quiescence achieved |
| RGN-004 | Child task force-terminated |
| RGN-005 | Quiescence timeout |

## Types

| Type | Role |
|------|------|
| `RegionId` | Unique region identifier (u64 newtype) |
| `RegionKind` | Enum: ConnectorLifecycle, HealthGate, Rollout, Fencing |
| `Region` | Core struct with tasks, children, quiescence budget |
| `TaskState` | Enum: Running, Draining, Completed, ForceTerminated |
| `RegionTask` | Task registered to a region (task_id, state, timestamp) |
| `CloseResult` | Result of close(): quiescence_achieved, tasks_drained, tasks_force_terminated |
| `RegionEvent` | Structured event emitted during region lifecycle |
| `RegionError` | Error enum: AlreadyClosed, TaskNotFound |

## Gate Behavior

The verification gate (`scripts/check_region_ownership.py`) validates:

1. Rust module exists at `crates/franken-node/src/connector/region_ownership.rs`
2. Spec doc exists at `docs/specs/region_tree_topology.md`
3. Integration test exists at `tests/integration/region_owned_lifecycle.rs`
4. Quiescence trace exists at `artifacts/10.15/region_quiescence_trace.jsonl`
5. All 7 required types present in module source
6. All 5 event code constants present in module source
7. All 4 region kinds present as enum variants
8. Spec doc contains required sections (Region Hierarchy, Ownership Rules, Quiescence Guarantees, Event Codes)
9. Quiescence trace is valid JSONL with open and close events

28 checks total. Exit code 0 on PASS, 1 on FAIL. Supports `--json` for
structured output and `--self-test` for self-validation.

## Acceptance Criteria

1. `Region` struct tracks parent/child relationships with `RegionId`
2. `register_task()` / `complete_task()` manage task lifecycle
3. `close()` drains all tasks within budget, force-terminates stragglers
4. Closed region rejects new task registration with `RegionError::AlreadyClosed`
5. All event codes RGN-001 through RGN-005 emitted as constants
6. `build_lifecycle_hierarchy()` factory creates canonical 4-region tree
7. `generate_quiescence_trace()` produces deterministic JSONL output
8. Gate script and test suite pass

## Artifacts

| Artifact | Path |
|----------|------|
| Rust module | `crates/franken-node/src/connector/region_ownership.rs` |
| Spec doc | `docs/specs/region_tree_topology.md` |
| Spec contract | `docs/specs/section_10_15/bd-2tdi_contract.md` |
| Integration test | `tests/integration/region_owned_lifecycle.rs` |
| Gate script | `scripts/check_region_ownership.py` |
| Test suite | `tests/test_check_region_ownership.py` |
| Quiescence trace | `artifacts/10.15/region_quiescence_trace.jsonl` |
| Verification evidence | `artifacts/section_10_15/bd-2tdi/verification_evidence.json` |
| Verification summary | `artifacts/section_10_15/bd-2tdi/verification_summary.md` |
