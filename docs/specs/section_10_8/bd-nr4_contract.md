# bd-nr4 -- Operator Runbooks for High-Severity Trust Incidents

## Overview

Section 10.8 (Operational Readiness) requires standardized operator runbooks
for six high-severity trust incident categories.  Each runbook provides a
deterministic, step-by-step response protocol covering containment,
investigation, repair, verification, and rollback.  Runbooks are delivered in
both Markdown (human-readable) and JSON (machine-parseable) formats, with a
formal JSON Schema for automated validation.

Runbooks are **drill-tested**: every category includes a drill scenario that
operators must execute within a 30-day freshness window to maintain operational
readiness.

## Incident Categories

| # | Category | Runbook ID | Severity |
|---|----------|------------|----------|
| 1 | Trust state corruption | RB-001 | critical |
| 2 | Mass revocation event | RB-002 | critical |
| 3 | Fleet quarantine activation | RB-003 | high |
| 4 | Epoch transition failure | RB-004 | critical |
| 5 | Evidence ledger divergence | RB-005 | high |
| 6 | Proof pipeline outage | RB-006 | high |

## Runbook Schema

Every JSON runbook conforms to the schema at `fixtures/runbooks/runbook_schema.json`.

Required fields:

| Field | Type | Description |
|-------|------|-------------|
| `runbook_id` | string | Unique identifier (RB-NNN) |
| `title` | string | Human-readable title |
| `category` | string | Snake_case category identifier |
| `severity` | enum | `critical` or `high` |
| `detection_signature` | object | `metrics` (string[]) + `log_patterns` (string[]) |
| `estimated_recovery_time` | string | Duration (e.g. "30m", "2h") |
| `required_permissions` | string[] | Required operator roles |
| `steps` | object | Five phases: containment, investigation, repair, verification, rollback |
| `cross_references` | string[] | Related beads, modules, and runbooks |
| `drill_scenario` | string | Description of drill exercise |

Each `steps` phase is an array of strings, one per action.

## Event Codes

| Code | Trigger | Severity |
|------|---------|----------|
| ORB-001 | Runbook activated (operator begins incident response) | INFO |
| ORB-002 | Step completed (operator advances to next phase) | INFO |
| ORB-003 | Runbook completed (all phases finished, incident resolved) | INFO |
| ORB-004 | Drill executed (scheduled drill for freshness validation) | INFO |

## Invariants

- **INV-ORB-COMPLETE** -- All six incident categories have corresponding
  runbooks in both Markdown and JSON formats.  No category is left uncovered.

- **INV-ORB-SCHEMA** -- All JSON runbooks validate against the canonical
  `runbook_schema.json`.  Every required field is present and correctly typed.

- **INV-ORB-DRILL** -- Every runbook includes a non-empty `drill_scenario`
  field describing how to exercise the runbook without a real incident.

- **INV-ORB-FRESH** -- Drill exercises must be executed within a 30-day
  freshness window.  Stale drills trigger operator alerts.

## File Layout

```
docs/runbooks/
  trust_state_corruption.md
  mass_revocation_event.md
  fleet_quarantine_activation.md
  epoch_transition_failure.md
  evidence_ledger_divergence.md
  proof_pipeline_outage.md

fixtures/runbooks/
  runbook_schema.json
  rb_001_trust_state_corruption.json
  rb_002_mass_revocation_event.json
  rb_003_fleet_quarantine_activation.json
  rb_004_epoch_transition_failure.json
  rb_005_evidence_ledger_divergence.json
  rb_006_proof_pipeline_outage.json
```

## Cross-References

| Runbook | Related Beads & Modules |
|---------|------------------------|
| RB-001 | bd-k6o (safe mode), safe_mode.rs, state_model.rs |
| RB-002 | bd-f2y (revocation), revocation.rs |
| RB-003 | bd-3o6 (fleet quarantine), health_gate.rs |
| RB-004 | bd-k6o (safe mode), fencing.rs |
| RB-005 | evidence ledger, transparency_log |
| RB-006 | proof pipeline, verification subsystem |

## Detection and Alerting

Each runbook defines detection signatures consisting of:

1. **Metrics** -- Prometheus-style metric conditions that trigger alerting
   (e.g. `trust_integrity_check_failures > 0`).
2. **Log patterns** -- Structured log patterns that operators or log
   aggregation systems should watch for (e.g. `TRUST_STATE_CORRUPTION_DETECTED`).

## Drill Requirements

Drills validate operator readiness without requiring a real incident:

- Each drill simulates the detection signature for its category.
- Operators execute the runbook end-to-end in a staging environment.
- Drill completion is logged as ORB-004.
- Drill freshness is tracked; stale drills (>30 days) generate alerts.
- Drill results are persisted for audit trail purposes.

## Acceptance Criteria

1. Six Markdown runbooks exist in `docs/runbooks/`, one per incident category,
   each containing detection, containment, investigation, repair, verification,
   and rollback sections.
2. Six JSON runbooks exist in `fixtures/runbooks/`, each conforming to
   `runbook_schema.json` with all required fields present and correctly typed.
3. The JSON schema at `fixtures/runbooks/runbook_schema.json` is a valid
   JSON Schema (draft-07 or later) that covers all required fields.
4. Every JSON runbook has a non-empty `drill_scenario` field.
5. Every JSON runbook has a non-empty `cross_references` array.
6. Event codes ORB-001 through ORB-004 are documented in the spec.
7. Invariants INV-ORB-COMPLETE, INV-ORB-SCHEMA, INV-ORB-DRILL, and
   INV-ORB-FRESH are documented in the spec.
8. Verification script `scripts/check_operator_runbooks.py` passes all checks
   with `--json` output and supports `--self-test`.
9. Unit tests in `tests/test_check_operator_runbooks.py` pass.

## Dependencies

- bd-k6o (safe mode) -- referenced by trust state corruption and epoch
  transition failure runbooks.
- bd-f2y (structured observability) -- referenced by mass revocation runbook.
- bd-3o6 (fleet operations) -- referenced by fleet quarantine runbook.
