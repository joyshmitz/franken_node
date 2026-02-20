# bd-29w6: Offline Coverage Tracker and SLO Dashboards

## Purpose

Compute offline coverage metrics continuously per policy scope. SLO breach alerts trigger automatically. Dashboard values are traceable to raw events.

## Invariants

- **INV-OCT-CONTINUOUS**: Coverage is recomputed on every event, not just at query time.
- **INV-OCT-SLO-BREACH**: SLO breach alerts fire when metric drops below threshold.
- **INV-OCT-TRACEABLE**: Every dashboard metric links back to contributing events.
- **INV-OCT-DETERMINISTIC**: Same events → same metric values.

## Types

### SloTarget

SLO target: metric_name, threshold (f64), breach_action.

### CoverageEvent

Raw event: artifact_id, available (bool), timestamp, scope.

### CoverageMetrics

Computed metrics: coverage_ratio, availability_ratio, repair_debt_count.

### SloBreachAlert

Alert record: slo_name, actual_value, threshold, breach_time, trace_id.

### OfflineCoverageTracker

Tracker that ingests events, computes metrics, checks SLOs.

## Functions

- `record_event(event)` → updates metrics
- `compute_metrics(scope)` → `CoverageMetrics`
- `check_slos(targets)` → `Vec<SloBreachAlert>`
- `dashboard_snapshot(trace_id, timestamp)` → dashboard JSON

## Error Codes

- `OCT_SLO_BREACH` — SLO target violated
- `OCT_INVALID_EVENT` — event missing required fields
- `OCT_NO_EVENTS` — no events recorded for scope
- `OCT_SCOPE_UNKNOWN` — unknown scope requested
