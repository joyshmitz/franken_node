# bd-3lh: Cold-Start and P99 Latency Gates for Core Workflows

## Bead: bd-3lh | Section: 10.6

## Purpose

Establish enforceable CI gates that block merges when cold-start time or p99
latency exceeds profile-specific thresholds across core workflows. Prevents
silent performance regressions from accumulating across releases.

## Core Workflows

| Workflow | Description |
|----------|-------------|
| migration_scan | Migration scanner audit of a project |
| compatibility_check | Compatibility matrix evaluation |
| policy_evaluation | Policy gate evaluation for a request |
| trust_card_lookup | Trust card materialization from registry |
| incident_replay | Incident bundle replay execution |

## Deployment Profiles

| Profile | Context | Cold-Start Budget | P99 Budget |
|---------|---------|-------------------|------------|
| dev_local | Developer laptop, iterative workflow | 500ms | 50ms |
| ci_dev | CI pipeline, high iteration count | 200ms | 20ms |
| enterprise | Enterprise production, strict SLA | 100ms | 10ms |

## Budget Configuration

Budgets are stored in `perf/budgets.toml` and version-controlled:

```toml
[profiles.dev_local]
cold_start_ms = 500
p99_latency_ms = 50

[profiles.ci_dev]
cold_start_ms = 200
p99_latency_ms = 20

[profiles.enterprise]
cold_start_ms = 100
p99_latency_ms = 10
```

Per-workflow overrides allow tighter or looser budgets where justified.

## Event Codes

| Code | Trigger |
|------|---------|
| LG-001 | Latency gate check started for a workflow. |
| LG-002 | Benchmark iteration completed with timing sample. |
| LG-003 | P99 computation completed for workflow. |
| LG-004 | Budget check passed for workflow. |
| LG-005 | Budget check failed: measured value exceeds threshold. |
| LG-006 | Early warning: workflow at >= 80% of budget. |
| LG-007 | Flamegraph evidence generated for regression. |
| LG-008 | Gate completed: overall pass/fail. |

## Invariants

| ID | Statement |
|----|-----------|
| INV-LG-MIN-SAMPLES | Minimum 30 iterations after warmup discard for statistical validity. |
| INV-LG-PROFILE-SPECIFIC | Budgets are profile-specific; no single threshold for all contexts. |
| INV-LG-VERSIONED-BUDGETS | Budget changes require version-controlled TOML updates with justification. |
| INV-LG-EARLY-WARNING | 80% threshold triggers early warning before hard failure at 100%. |
| INV-LG-STRUCTURED-OUTPUT | Gate produces structured JSON with workflow, measured value, budget, and verdict. |

## Quantitative Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| Minimum iterations | >= 30 | Count after warmup discard |
| Warmup discard | >= 5 | First N iterations discarded |
| P99 computation accuracy | +/- 1ms | Percentile from sorted sample |
| Early warning threshold | 80% of budget | measured / budget ratio |
| Gate failure threshold | 100% of budget | measured > budget |

## Gate Output Schema

```json
{
  "profile": "ci_dev",
  "timestamp_utc": "2026-02-21T00:00:00Z",
  "workflows": [
    {
      "name": "migration_scan",
      "cold_start_ms": 150.0,
      "cold_start_budget_ms": 200,
      "cold_start_pass": true,
      "cold_start_warning": true,
      "p99_latency_ms": 15.0,
      "p99_budget_ms": 20,
      "p99_pass": true,
      "p99_warning": true,
      "iterations": 30,
      "p50_ms": 10.0,
      "p95_ms": 14.0
    }
  ],
  "overall_pass": true,
  "warnings": 2,
  "failures": 0
}
```

## Testing & Logging Requirements

- Unit tests for budget TOML parsing and profile selection.
- Unit tests for p99 computation from synthetic timing data.
- Unit tests for gate pass/fail logic with mock data.
- Integration test with known-good fixture verifies pass.
- Integration test with artificially slow fixture verifies failure.
- Structured logs: LG-001 through LG-008 with workflow name and timing data.

## Expected Artifacts

- `perf/budgets.toml` — budget definitions
- `docs/specs/section_10_6/bd-3lh_contract.md` — this specification
- `scripts/check_latency_gates.py` — verification script
- `tests/test_check_latency_gates.py` — unit tests
- `artifacts/section_10_6/bd-3lh/verification_evidence.json` — CI evidence
- `artifacts/section_10_6/bd-3lh/verification_summary.md` — human summary
