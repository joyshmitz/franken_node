# bd-qlc6 — Lane-Aware Scheduler Classes with Priority Policies

**Section:** 10.14 — Remote Capabilities & Protocol Testing
**Status:** Implemented

## Overview

Maps incoming task types to scheduler lanes based on declarative policy
configuration. Enforces starvation detection, misclassification rejection,
and exposes per-lane telemetry counters.

## Scheduler Lanes

| Lane | Priority Weight | Concurrency Cap | Purpose |
|------|----------------|-----------------|---------|
| ControlCritical | 100 | 8 | Epoch transitions, barrier coordination, marker writes |
| RemoteEffect | 50 | 32 | Remote computation invocations, artifact uploads |
| Maintenance | 20 | 4 | Garbage collection, compaction, cleanup tasks |
| Background | 10 | 2 | Telemetry export, log rotation, low-priority housekeeping |

## Well-Known Task Classes (10)

| Task Class | Target Lane |
|------------|-------------|
| epoch_transition | ControlCritical |
| barrier_coordination | ControlCritical |
| marker_write | ControlCritical |
| remote_computation | RemoteEffect |
| artifact_upload | RemoteEffect |
| artifact_eviction | RemoteEffect |
| garbage_collection | Maintenance |
| compaction | Maintenance |
| telemetry_export | Background |
| log_rotation | Background |

## Invariants

| ID | Statement |
|----|-----------|
| INV-LANE-EXACT-MAP | Every task class maps to exactly one lane |
| INV-LANE-STARVATION-DETECT | Starved lanes trigger alert within 2x starvation window |
| INV-LANE-MISCLASS-REJECT | Unrecognized task classes are rejected |
| INV-LANE-CAP-ENFORCE | Lane active count never exceeds concurrency cap |
| INV-LANE-TELEMETRY-ACCURATE | Counters match actual task lifecycle events |
| INV-LANE-HOT-RELOAD | Policy changes take effect without restart |

## Event Codes (10)

LANE_ASSIGN, LANE_STARVED, LANE_MISCLASS, LANE_METRICS,
LANE_TASK_STARTED, LANE_TASK_COMPLETED, LANE_CAP_REACHED,
LANE_POLICY_RELOADED, LANE_CREATED, LANE_STARVATION_CLEARED

## Error Codes (8)

ERR_LANE_UNKNOWN_CLASS, ERR_LANE_CAP_EXCEEDED, ERR_LANE_UNKNOWN_LANE,
ERR_LANE_DUPLICATE, ERR_LANE_INVALID_POLICY, ERR_LANE_STARVATION,
ERR_LANE_TASK_NOT_FOUND, ERR_LANE_INVALID_WEIGHT

## Operations

| Operation | Description |
|-----------|-------------|
| assign_task | Resolve class → lane, enforce cap, record audit |
| complete_task | Release lane resources, update counters |
| check_starvation | Detect starved lanes based on queue depth and elapsed time |
| reload_policy | Hot-reload mapping policy without restart |
| telemetry_snapshot | Export per-lane counter snapshot |
| export_audit_log_jsonl | Export audit log as JSONL (schema ls-v1.0) |

## Key Types

- `SchedulerLane` — enum with 4 lanes
- `TaskClass` — string-wrapped task discriminant
- `LaneConfig` — per-lane priority weight, concurrency cap, starvation window
- `MappingRule` — task class → lane mapping
- `LaneMappingPolicy` — lane configs + mapping rules with validation
- `LaneCounters` — per-lane runtime counters
- `LaneScheduler` — the scheduler itself
- `TaskAssignment` — assignment record with trace ID
- `LaneAuditRecord` — JSONL audit record
- `LaneTelemetrySnapshot` — telemetry export

## Schema Version

`ls-v1.0`

## Acceptance Criteria

1. 4 scheduler lanes with distinct priority weights
2. 10 well-known task classes mapped to lanes
3. Starvation detection within 2x configured window
4. Concurrency cap enforcement per lane
5. Unknown task class rejection
6. Hot-reload policy without restart
7. JSONL audit log export with schema version
8. Telemetry snapshot with accurate counters
9. 30+ inline Rust tests
10. Verification gate with 35+ checks
