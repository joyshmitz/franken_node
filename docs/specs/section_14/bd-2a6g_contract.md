# bd-2a6g — Containment/Revocation Latency and Convergence Metrics

**Section:** 14 — Benchmark & reporting
**Bead:** bd-2a6g
**Status:** Implementation

## Overview

Instruments latency from containment or revocation event initiation to full
convergence across the trust network. Tracks five event categories with
per-category SLO thresholds, percentile latency computation, and convergence
ratio measurement.

## Event Categories

| Category              | Default SLO (ms) |
|-----------------------|-------------------|
| Revocation            | 5000              |
| Quarantine            | 2000              |
| PolicyEnforcement     | 10000             |
| TrustDowngrade        | 3000              |
| EmergencyContainment  | 1000              |

## Capabilities

- **Event recording**: `record_event` with latency validation
- **Convergence measurement**: Tracks nodes_total, nodes_converged, convergence ratio
- **Percentile computation**: p50/p95/p99 latency per category
- **SLO gating**: Per-category threshold enforcement with breach flagging
- **Report generation**: `generate_report` with category aggregation
- **Audit logging**: All operations logged; JSONL export via `export_audit_log_jsonl`

## Event Codes

| Code         | Description                             |
|-------------|------------------------------------------|
| CRM-001     | Containment event recorded               |
| CRM-002     | Convergence measured                     |
| CRM-003     | Percentiles computed                     |
| CRM-004     | SLO checked                              |
| CRM-005     | Trend detected                           |
| CRM-006     | Report generated                         |
| CRM-007     | Category registered                      |
| CRM-008     | Convergence window closed                |
| CRM-009     | SLO threshold set                        |
| CRM-010     | Version embedded                         |
| CRM-ERR-001 | SLO breach                               |
| CRM-ERR-002 | Invalid event (negative latency)         |

## Invariants

| ID                     | Rule                                                      |
|------------------------|-----------------------------------------------------------|
| INV-CRM-PERCENTILE     | p50 <= p95 <= p99 always ordered                          |
| INV-CRM-CONVERGENCE    | Convergence time >= initiation-to-ack time                |
| INV-CRM-DETERMINISTIC  | Same inputs produce same report hash                      |
| INV-CRM-GATED          | Events exceeding SLO thresholds are flagged               |
| INV-CRM-VERSIONED      | Metric version embedded in every report                   |
| INV-CRM-AUDITABLE      | Every operation logged with event code                    |

## Types

- `EventCategory` — 5-variant enum with per-category SLOs
- `ConvergenceStatus` — 4-variant enum (Pending, Partial, Full, TimedOut)
- `Percentiles` — p50/p95/p99 with ordering validation
- `ContainmentEvent` — Event measurement with convergence data
- `CategoryMetrics` — Per-category aggregated statistics
- `ContainmentReport` — Full report with flagged categories
- `CrmAuditRecord` — Audit record with event code
- `ContainmentRevocationMetrics` — Engine managing events and reports

## Verification

- Gate script: `scripts/check_containment_revocation_metrics.py`
- Tests: `tests/test_check_containment_revocation_metrics.py`
- Min inline tests: 26
