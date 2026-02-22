# bd-cuut: Control-Plane Lane Mapping Policy

**Section:** 10.15 | **Type:** task | **Priority:** P1

## Overview

Defines the lane mapping policy for all control-plane workloads. Three lane
classes (Cancel, Timed, Ready) with explicit priority ordering, budget
allocations, and starvation detection. Builds on the canonical lane-aware
scheduler from bd-qlc6 (Section 10.14).

## Lane Classes

| Lane   | Budget | Priority | Starvation Threshold | Description |
|--------|--------|----------|---------------------|-------------|
| Cancel | >= 20% | 0 (highest) | 1 tick | Cancellation handlers, drain, region close, shutdown |
| Timed  | >= 30% | 1 | 2 ticks | Health checks, lease renewal, epoch transitions |
| Ready  | remainder (50%) | 2 (lowest) | 3 ticks | Background maintenance, telemetry, archival |

## Task Class Assignments (14 classes)

### Cancel Lane (4 classes)
- cancellation_handler, drain_operation, region_close, shutdown_handler

### Timed Lane (5 classes)
- health_check, lease_renewal, epoch_transition, barrier_coordination, marker_append

### Ready Lane (5 classes)
- telemetry_flush, evidence_archival, compaction, garbage_collection, log_rotation

## Invariants

| ID | Rule |
|----|------|
| INV-CLM-COMPLETE-MAP | Every control-plane task class has a lane assignment |
| INV-CLM-BUDGET-SUM | Lane budget allocations sum to <= 100% |
| INV-CLM-CANCEL-PRIORITY | Cancel-lane tasks scheduled before Ready-lane when both pending |
| INV-CLM-STARVATION-DETECT | Starvation detected if zero slots for N consecutive ticks |
| INV-CLM-CANCEL-MIN-BUDGET | Cancel lane gets >= 20% of capacity |
| INV-CLM-TIMED-MIN-BUDGET | Timed lane gets >= 30% of capacity |

## Event Codes

| Code | Description |
|------|-------------|
| CLM_TASK_ASSIGNED | Task assigned to lane |
| CLM_STARVATION_ALERT | Lane starvation detected |
| CLM_BUDGET_VIOLATION | Budget allocation violated |
| CLM_POLICY_LOADED | Lane policy loaded |
| CLM_PRIORITY_OVERRIDE | Priority override applied |
| CLM_TICK_COMPLETE | Scheduler tick completed |
| CLM_METRICS_EXPORTED | Metrics snapshot exported |
| CLM_STARVATION_CLEARED | Lane starvation cleared |

## Error Codes

| Code | Trigger |
|------|---------|
| ERR_CLM_UNKNOWN_TASK | Task class not in policy |
| ERR_CLM_BUDGET_OVERFLOW | Budget allocations exceed 100% |
| ERR_CLM_STARVATION | Lane starved beyond threshold |
| ERR_CLM_INVALID_BUDGET | Budget below minimum for lane |
| ERR_CLM_DUPLICATE_TASK | Duplicate task class registration |
| ERR_CLM_INCOMPLETE_MAP | Policy missing required assignments |

## Schema Version

`clm-v1.0`

## Acceptance Criteria

- Every control task class has lane assignment and budget policy
- Cancel-lane tasks never starved beyond 1-tick threshold
- Budget allocations enforced: cancel >= 20%, timed >= 30%, sum <= 100%
- Lane assignments are machine-readable via BTreeMap
- Starvation metrics exportable as CSV: tick, per-lane tasks_run, per-lane starved
- JSONL audit log with schema_version field

## Artifacts

- `crates/franken-node/src/control_plane/control_lane_mapping.rs`
- `docs/specs/section_10_15/bd-cuut_contract.md`
- `scripts/check_control_lane_mapping.py`
- `tests/test_check_control_lane_mapping.py`
- `artifacts/section_10_15/bd-cuut/verification_evidence.json`
- `artifacts/section_10_15/bd-cuut/verification_summary.md`
