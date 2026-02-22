# bd-2tdi: Migrate Lifecycle/Rollout Orchestration to Region-Owned Execution Trees

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
root
  +-- lifecycle
  |     +-- health-gate
  |     +-- rollout
  |     +-- fencing
```

| Region | Parent | Purpose |
|--------|--------|---------|
| root | (none) | Top-level orchestrator region |
| lifecycle | root | Groups all lifecycle-related subtasks |
| health-gate | lifecycle | Health-check probes and readiness gates |
| rollout | lifecycle | Rolling update state transitions |
| fencing | lifecycle | Distributed fencing token acquisition |

## Ownership Rules

1. **Single parent**: Every region except root has exactly one parent region.
2. **No re-parenting**: Once a region is created under a parent, it cannot be moved.
3. **Task scoping**: Tasks registered to a region are owned by that region; they
   cannot outlive the region.
4. **Hierarchical close**: Closing a region first closes all child regions
   recursively, then drains its own registered tasks.
5. **Force-terminate budget**: If a region does not reach quiescence within the
   configured drain budget (milliseconds), remaining tasks are force-terminated.

## Quiescence Guarantees

| Level | Guarantee |
|-------|-----------|
| Leaf region (no children) | All registered tasks complete or are force-terminated within budget |
| Interior region | All child regions reach quiescence, then own tasks drain |
| Root | Full tree quiescence before returning from close() |

## Invariants

| ID | Statement |
|----|-----------|
| INV-REGION-QUIESCENCE | A region's close() blocks until all children and own tasks reach quiescence or budget expires |
| INV-REGION-NO-OUTLIVE | No task registered to a region may outlive that region's Closed state |
| INV-REGION-DETERMINISTIC-CLOSE | The close sequence is deterministic: children first (in insertion order), then own tasks |

## Event Codes

| Code | Description |
|------|-------------|
| REG-001 | Region opened |
| REG-002 | Task registered to region |
| REG-003 | Region drain started |
| REG-004 | Region drain completed (quiescence reached) |
| REG-005 | Region force-terminate triggered (budget exceeded) |
| REG-006 | Region closed |
| REG-007 | Child region attached |
| REG-008 | Task deregistered from region |

## Gate Behavior

The verification gate (`scripts/check_region_tree_topology.py`) validates:

1. Rust module exists at `crates/franken-node/src/runtime/region_tree.rs`
2. Module is wired in `runtime/mod.rs`
3. Spec contract exists
4. All three invariant constants are present in source
5. All eight event code constants are present in source
6. Quiescence trace artifact exists
7. Unit tests are present (`#[cfg(test)]`)
8. Core types exist: `RegionId`, `RegionState`, `RegionTree`, `RegionHandle`
9. Core operations exist: `open_region`, `register_task`, `close`, `force_terminate`

Exit code 0 on PASS, 1 on FAIL. Supports `--json` for structured output and
`--self-test` for self-validation.

## Error Codes

| Code | Description |
|------|-------------|
| ERR_REGION_NOT_FOUND | Referenced region ID does not exist in the tree |
| ERR_REGION_ALREADY_CLOSED | Attempted operation on a Closed region |
| ERR_REGION_PARENT_NOT_FOUND | Parent region ID does not exist |
| ERR_REGION_BUDGET_EXCEEDED | Drain budget exceeded; force-terminate invoked |

## Acceptance Criteria

1. `RegionTree` struct tracks parent/child relationships with `RegionId`
2. `RegionHandle` provides scoped task registration
3. `close()` drains children recursively, then own tasks, within budget
4. Force-terminate after budget exceeded
5. All event codes REG-001 through REG-008 emitted as constants
6. All invariants documented as constants
7. Quiescence trace artifact at `artifacts/10.15/region_quiescence_trace.jsonl`
8. Gate script and test suite pass

## Dependencies

- **Upstream**: bd-qlc6 (lane scheduler, 10.14)
- **Downstream**: section 10.15 gate

## Artifacts

| Artifact | Path |
|----------|------|
| Rust module | `crates/franken-node/src/runtime/region_tree.rs` |
| Spec contract | `docs/specs/section_10_15/bd-2tdi_contract.md` |
| Gate script | `scripts/check_region_tree_topology.py` |
| Test suite | `tests/test_check_region_tree_topology.py` |
| Quiescence trace | `artifacts/10.15/region_quiescence_trace.jsonl` |
| Verification evidence | `artifacts/section_10_15/bd-2tdi/verification_evidence.json` |
| Verification summary | `artifacts/section_10_15/bd-2tdi/verification_summary.md` |
