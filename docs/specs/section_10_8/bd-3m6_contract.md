# bd-3m6 -- Disaster-Recovery Drills for Control-Plane Failures

## Overview

Section 10.8 (Operational Readiness) requires automated disaster-recovery drills
that exercise the operator runbooks (bd-nr4) against deterministic fault
injection scenarios.  Drills measure recovery time against SLOs, persist
results as compliance evidence, and flag staleness when scenarios have not been
drilled within their configured freshness window.

## Drill Scenarios

| ID | Scenario | Severity | SLO |
|----|----------|----------|-----|
| DR-001 | Evidence ledger loss | high | Recovery < 5m |
| DR-002 | Trust artifact corruption | critical | Repair < 2m |
| DR-003 | Epoch barrier failure | critical | Hold-and-retry < 3m |
| DR-004 | Federation partition | high | Reconciliation < 10m |
| DR-005 | Proof pipeline outage | high | Queue-and-recover < 5m |

## Drill Framework

### Scheduling

- Drills run on configurable recurring intervals.
- Default: weekly for `critical` severity, monthly for `high` severity.
- Freshness window: if a drill has not been executed within 2x its interval,
  it is flagged as stale.

### Execution

1. **Pre-check** -- Verify drill environment is healthy and isolated.
2. **Fault injection** -- Apply deterministic, reproducible fault.
3. **Runbook execution** -- Execute the corresponding runbook steps (bd-nr4).
4. **Recovery measurement** -- Record wall-clock time from injection to verified
   recovery.
5. **Post-check** -- Verify system state is restored, no residual artifacts.
6. **Result persistence** -- Write structured JSON result as compliance evidence.

### Fault Injection

Faults are deterministic and precisely specified:

| Scenario | Fault Description |
|----------|-------------------|
| DR-001 | Delete ledger data files in isolated test environment |
| DR-002 | Inject bitflip in trust artifact checksum field |
| DR-003 | Simulate epoch transition timeout via mock clock |
| DR-004 | Network partition between federation peers via firewall rules |
| DR-005 | Kill proof generation service process |

### Abort Safety

If a drill detects unexpected state during execution:

1. Immediately halt the drill.
2. Log the anomaly at ERROR level.
3. Alert operators via incident channel.
4. Restore pre-drill state from checkpoint.
5. Record drill result as `aborted` with anomaly description.

Drills must never leave the system in a worse state than before execution.

### Idempotency

Running the same drill scenario twice in succession must:
- Produce consistent results (within measurement noise).
- Not leave residual state from the first run.
- Not depend on the first run having occurred.

## Event Codes

| Code | Trigger | Severity |
|------|---------|----------|
| DRD-001 | Drill scheduled (cron trigger or manual) | INFO |
| DRD-002 | Fault injected (drill begins) | WARN |
| DRD-003 | Recovery verified (drill completes successfully) | INFO |
| DRD-004 | Drill failed (SLO exceeded or recovery incorrect) | ERROR |
| DRD-005 | Drill aborted (unexpected state detected) | ERROR |
| DRD-006 | Drill stale (freshness window exceeded) | WARN |

## Invariants

- **INV-DRD-DETERMINISTIC** -- All fault injection is deterministic and
  reproducible.  No random chaos engineering.  Identical inputs produce
  identical faults.

- **INV-DRD-ISOLATED** -- Drills execute in isolated environments.  No
  accidental production impact.  Fault scope is bounded to drill target.

- **INV-DRD-MEASURED** -- Every drill records wall-clock recovery time and
  compares against the scenario SLO.  SLO violations are explicit failures.

- **INV-DRD-EVIDENCE** -- Drill results are persisted as structured JSON under
  the `required` retention class (bd-f2y).  Results include drill ID, scenario,
  timestamp, recovery time, SLO status, and anomalies.

- **INV-DRD-ABORT-SAFE** -- If unexpected state is detected during a drill,
  execution halts immediately with operator alert.  Pre-drill state is restored.

## Result Schema

Each drill result is a JSON object:

```json
{
  "drill_id": "DR-001-20260220T1400Z",
  "scenario": "evidence_ledger_loss",
  "scenario_id": "DR-001",
  "timestamp": "2026-02-20T14:00:00Z",
  "fault_description": "Delete ledger data files in isolated test environment",
  "recovery_steps": ["detect", "restore_from_backup", "verify_consistency"],
  "recovery_time_seconds": 180,
  "slo_seconds": 300,
  "slo_met": true,
  "status": "pass",
  "anomalies": []
}
```

## SLO Configuration

SLOs are defined per scenario in the drill definition files:

| Scenario | SLO (seconds) | Severity | Drill Interval |
|----------|---------------|----------|----------------|
| DR-001 | 300 | high | monthly |
| DR-002 | 120 | critical | weekly |
| DR-003 | 180 | critical | weekly |
| DR-004 | 600 | high | monthly |
| DR-005 | 300 | high | monthly |

## Compliance Evidence

Drill results constitute compliance evidence per bd-f2y retention policy:
- Retention class: `required`
- Minimum retention: 1 year
- Format: JSON (machine-readable)
- Location: `artifacts/drills/` (production) or `fixtures/drills/` (definitions)

## Cross-References

| Component | Reference |
|-----------|-----------|
| Operator runbooks | bd-nr4, `docs/runbooks/` |
| Safe mode | bd-k6o, `safe_mode.rs` |
| Incident retention | bd-f2y |
| Evidence ledger | `evidence_ledger` module |
| Trust artifacts | `state_model.rs` |
| Epoch management | `fencing.rs` |
| Proof pipeline | proof generation subsystem |

## File Layout

```
fixtures/drills/
  drill_schema.json
  dr_001_evidence_ledger_loss.json
  dr_002_trust_artifact_corruption.json
  dr_003_epoch_barrier_failure.json
  dr_004_federation_partition.json
  dr_005_proof_pipeline_outage.json

docs/specs/section_10_8/bd-3m6_contract.md  (this file)
scripts/check_dr_drills.py
tests/test_check_dr_drills.py
artifacts/section_10_8/bd-3m6/verification_evidence.json
artifacts/section_10_8/bd-3m6/verification_summary.md
```

## Acceptance Criteria

1. All 5 drill scenario definition files exist in `fixtures/drills/`.
2. A drill schema (`fixtures/drills/drill_schema.json`) validates all definitions.
3. Each scenario specifies: fault description, recovery steps, SLO, severity, and
   drill interval.
4. Event codes DRD-001 through DRD-006 are documented.
5. Invariants INV-DRD-DETERMINISTIC, INV-DRD-ISOLATED, INV-DRD-MEASURED,
   INV-DRD-EVIDENCE, and INV-DRD-ABORT-SAFE are documented.
6. Verification script passes all checks.
7. Unit tests pass.

## Dependencies

- bd-nr4 (operator runbooks) — drills execute runbook procedures
- bd-f2y (incident bundle retention) — drill results are compliance evidence
- bd-k6o (safe mode) — some drills trigger safe-mode entry
