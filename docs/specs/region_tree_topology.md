# Region Tree Topology

**Bead:** bd-2tdi | **Section:** 10.15 | **HRI:** #2 (Region-Owned Lifecycle)

## Region Hierarchy

```text
root_region (ConnectorLifecycle)
├── health_gate_region (HealthGate)
├── rollout_region (Rollout)
└── fencing_region (Fencing)
```

### Root Region: ConnectorLifecycle

- **Scope**: Entire connector lifecycle (Discovered -> Active -> Stopped)
- **Budget**: 5000ms quiescence timeout
- **Owns**: All child regions for health-gate, rollout, and fencing operations
- **Invariant**: `root.close()` implies all child regions are closed and all tasks drained

### Child: HealthGate

- **Scope**: Single health-gate evaluation cycle
- **Budget**: 2000ms quiescence timeout
- **Parent**: ConnectorLifecycle root region
- **Tasks**: Health check evaluations, gate scoring

### Child: Rollout

- **Scope**: Rollout state transition (Shadow -> Canary -> Ramp -> Default)
- **Budget**: 3000ms quiescence timeout
- **Parent**: ConnectorLifecycle root region
- **Tasks**: State transition writes, epoch-scoped persistence

### Child: Fencing

- **Scope**: Fencing token acquisition and release
- **Budget**: 2000ms quiescence timeout
- **Parent**: ConnectorLifecycle root region
- **Tasks**: Lease acquisition, fenced writes, token release

## Ownership Rules

1. A region MUST be created before spawning any tasks it will own.
2. Tasks MUST be registered with `region.register_task()` before execution.
3. Task completion MUST be reported with `region.complete_task()`.
4. `region.close()` drains all tasks; tasks exceeding the quiescence budget are force-terminated.
5. No task spawned within a region may outlive that region.
6. Child regions MUST be closed before their parent region.

## Quiescence Guarantees

| Level | Guarantee |
|-------|-----------|
| Root | All child regions closed, all tasks in terminal state |
| Health-Gate | Current evaluation cycle completed or force-terminated |
| Rollout | Current transition completed or rolled back |
| Fencing | All held tokens released |

## Event Codes

| Code | Event | Description |
|------|-------|-------------|
| `RGN-001` | Region opened | New region created with parent linkage |
| `RGN-002` | Region close initiated | Close requested, drain phase begins |
| `RGN-003` | Quiescence achieved | All tasks completed within budget |
| `RGN-004` | Child task force-terminated | Task exceeded budget, forcibly terminated |
| `RGN-005` | Quiescence timeout | Budget exceeded, force-termination occurred |

## Implementation

- Module: `crates/franken-node/src/connector/region_ownership.rs`
- Types: `Region`, `RegionId`, `RegionKind`, `TaskState`, `RegionTask`, `CloseResult`
- Builder: `build_lifecycle_hierarchy()` constructs the complete region tree
- Trace: `generate_quiescence_trace()` produces JSONL event log
