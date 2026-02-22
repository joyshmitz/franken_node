# bd-lus: Product Scheduler Lanes + Global Bulkhead Integration

## Purpose

Integrate canonical lane-aware scheduling and global remote bulkhead controls into
product runtime operations. This contract defines lane assignment, per-lane
capacity/overflow behavior, global in-flight protection, runtime reload
semantics, and structured telemetry.

## Lane Taxonomy

- `cancel` (highest priority): cancellation handlers and drain operations.
- `timed`: deadline-aware transitions/checkpoints.
- `realtime` (`ready` accepted as alias): interactive control-plane calls.
- `background`: low-priority anti-entropy/maintenance/telemetry.

Priority order is strict:
`cancel > timed > realtime(ready) > background`.

## Invariants

- **INV-LR-LANE-ASSIGN**: every operation resolves to exactly one lane.
- **INV-LR-NO-STARVE-CANCEL**: cancel lane can still admit work while background is under pressure, bounded by global capacity.
- **INV-LR-LANE-CAP**: per-lane `max_concurrent` is never exceeded.
- **INV-LR-BULKHEAD-CAP**: total in-flight operations never exceed `remote_max_in_flight`.
- **INV-LR-BULKHEAD-FAIL-FAST**: saturation returns `BULKHEAD_OVERLOAD` with retry hint, no silent hang.
- **INV-LR-RELOAD-NEW-WORK-ONLY**: runtime config reload affects newly admitted operations; already in-flight operations keep prior assignments.
- **INV-LR-METRICS-DETERMINISTIC**: lane p99 queue wait is deterministic for identical sample sets.
- **INV-LR-DEFAULT-BACKGROUND**: unknown or missing lane hints default to background with explicit warning event.

## Implementation Surface

- `crates/franken-node/src/runtime/lane_router.rs`
  - Product lane enum and assignment logic from `CapabilityContext` + lane hints.
  - Per-lane concurrency/queue management with overflow policies.
  - Structured lane events and deterministic metrics snapshots.
  - Runtime config reload integration.
- `crates/franken-node/src/runtime/bulkhead.rs`
  - Product-layer global bulkhead with stable overload semantics and retry hints.
- `crates/franken-node/src/config.rs`
  - Runtime lane + bulkhead configuration model integrated into existing config resolution.

## Event Codes

Required stable events:

- `LANE_ASSIGNED`
- `LANE_SATURATED`
- `BULKHEAD_OVERLOAD`
- `LANE_CONFIG_RELOAD`

Additional explicit warning event:

- `LANE_DEFAULTED_BACKGROUND`

## Error Codes

- `LANE_SATURATED`
- `BULKHEAD_OVERLOAD`
- `OPERATION_UNKNOWN`
- `OPERATION_DUPLICATE`
- `CONFIG_INVALID`

## Metrics Contract

Per lane:

- `in_flight` (gauge)
- `queued` (gauge)
- `completed` (counter)
- `rejected` (counter)
- `p99_queue_wait_ms` (derived histogram percentile)

Global:

- `total_in_flight` (gauge)
- `bulkhead_rejections` (counter)

## Acceptance Criteria Mapping

1. **Lane assignment**: operations map from `CapabilityContext` metadata and/or hint; unknown hints default to background with warning.
2. **Per-lane control**: each lane has configurable concurrency and overflow behavior.
3. **Global bulkhead**: admissions fail with `BULKHEAD_OVERLOAD` when global cap is reached.
4. **Runtime reload**: lane/bulkhead config can be reloaded; changes apply to newly admitted operations.
5. **Priority ordering**: scheduler promotion and admission respect lane priority ordering.
6. **Metrics**: lane and global counters/gauges are exported in deterministic snapshot shape.
7. **Unit coverage**: assignment, caps, starvation behavior, reload, unknown-lane fallback, deterministic p99 are tested.
8. **Mixed workload integration**: 100-op simulation demonstrates global cap and lane behavior.

## Verification Artifacts

- Gate script: `scripts/check_scheduler_lanes.py`
- Gate tests: `tests/test_check_scheduler_lanes.py`
- Evidence: `artifacts/section_10_11/bd-lus/verification_evidence.json`
- Summary: `artifacts/section_10_11/bd-lus/verification_summary.md`
