# Telemetry Bridge E2E Summary

- **Trace ID**: `trace-bd-1now-4-6-telemetry-e2e`
- **Bead**: bd-1now.4.6
- **Verdict**: FAIL
- **Stages**: 7/13 passed

## Stage Results

| Stage | Status | Detail | Elapsed |
|-------|--------|--------|---------|
| compile | + PASS | clippy clean for frankenengine-node | 176.0s |
| unit-baseline | + PASS | 42 unit tests passed | 454.0s |
| normal-lifecycle | + PASS | single event ingested and persisted | 91.0s |
| multi-event | X FAIL | multi-event ingestion failed | 148.0s |
| abnormal-exit | X FAIL | abnormal exit handling broken | 150.0s |
| backpressure | X FAIL | backpressure handling broken | 140.0s |
| oversized-reject | X FAIL | oversized event not properly rejected | 151.0s |
| multi-conn | X FAIL | concurrent ingestion failed | 147.0s |
| worker-cleanup | X FAIL | orphan worker or cleanup failure | 142.0s |
| transitions | + PASS | LISTENER_STARTED → STATE_TRANSITION → DRAIN_STARTED → DRAIN_COMPLETE | 235.0s |
| key-format | + PASS | keys follow telemetry_NNNNN format | 89.0s |
| stale-recovery | + PASS | stale socket cleaned up before bind | 79.0s |
| event-fields | + PASS | bridge_id, code, detail, queue_capacity present | 0.0s |

## Artifact Locations

- Machine-readable summary: `artifacts/asupersync/bd-1now.4.6/telemetry_e2e_summary.json`
- Stage results (JSONL): `artifacts/asupersync/bd-1now.4.6/telemetry_e2e_stage_results.jsonl`
- Event log (JSONL): `artifacts/asupersync/bd-1now.4.6/telemetry_e2e_log.jsonl`
- Per-stage outputs: `artifacts/asupersync/bd-1now.4.6/stage_outputs/`

## Scenarios Covered

1. Normal startup, ingestion, orderly shutdown
2. Abnormal engine exit (non-zero code, signal kill)
3. Burst traffic exceeding backpressure capacity
4. Oversized event rejection (>64KB)
5. Multi-connection concurrent ingestion
6. Socket cleanup and worker-resolution after stop/join
7. Lifecycle state transition recording
8. Persistence key format verification
9. Stale socket recovery
10. Structured event field validation
