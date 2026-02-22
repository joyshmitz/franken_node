# bd-3gnh: Observability Dashboards for Asupersync Runtime Health

## Bead Identity

| Field | Value |
|-------|-------|
| Bead ID | bd-3gnh |
| Section | 10.15 |
| Title | Add observability dashboards for region health, obligation health, lane pressure, and cancel latency |
| Type | task |

## Purpose

The 10 Hard Runtime Invariants (Section 8.5) require real-time observability so
operators can detect invariant stress before user-facing outages. This bead adds
dashboards exposing core asupersync runtime health signals with alert thresholds
mapped to specific runbook actions (bd-1f8m).

## Dashboard Panels

| Panel | Metrics | Alert Threshold |
|-------|---------|-----------------|
| Region Health | open regions, closing regions, quiescence failures | quiescence failures > 0 in 5min → CRITICAL |
| Obligation Health | active obligations, committed/s, leaked total | obligation leaks > 0 → CRITICAL |
| Lane Pressure | per-lane task count, starvation counter | starvation > 3 consecutive ticks → WARNING |
| Cancel Latency | p50/p95/p99 per workflow | cancel p99 > budget → WARNING |

## Deliverables

| Artifact | Path |
|----------|------|
| Dashboard spec | `docs/observability/asupersync_control_dashboards.md` |
| Metrics module | `crates/franken-node/src/connector/observability_metrics.rs` |
| Check script | `scripts/check_observability_dashboards.py` |
| Test suite | `tests/test_check_observability_dashboards.py` |
| Evidence | `artifacts/section_10_15/bd-3gnh/verification_evidence.json` |
| Summary | `artifacts/section_10_15/bd-3gnh/verification_summary.md` |

## Invariants

- **INV-OBS-COVERAGE**: All four dashboard panels (region, obligation, lane,
  cancel) have defined metrics and alert thresholds.
- **INV-OBS-RUNBOOK-MAPPING**: Every alert links to a specific runbook action
  from bd-1f8m.
- **INV-OBS-SCHEMA**: Metrics use stable names, labels, and types (counter,
  gauge, histogram).

## Gate Contract

The check script (`scripts/check_observability_dashboards.py`) must:
- Emit `--json` output with `verdict`, `checks_passed`, `checks_total`
- Provide a `self_test()` function returning structured results
- Exit 0 on PASS, 1 on FAIL
