# bd-3o6 -- Adopt Canonical Structured Observability + Stable Error Taxonomy Contracts

## Overview

Section 9I.18 mandates a stable telemetry namespace and AI-recovery error
contract spanning every operational surface of franken_node.  The 10.13 chain
delivered the foundational contracts:

- **bd-1ugy** (`telemetry_namespace.md`) -- canonical metric names, dimensions,
  and cardinality budgets via `SchemaRegistry` / `MetricSchema`.
- **bd-novi** (`error_code_registry.md`) -- stable error taxonomy with
  `ErrorCodeRegistry`, `ErrorCodeEntry`, `RecoveryInfo`, and machine-readable
  recovery hints.

This bead enforces **adoption** of those contracts across all operational
surfaces: CLI commands, operational APIs, dashboard integrations, health
endpoints, and structured log output.

## Operational Surfaces

| Surface ID | Surface | Contract requirement |
|------------|---------|---------------------|
| OPS-CLI | CLI commands (`franken-node *`) | All `--json` output uses canonical metric names and error codes |
| OPS-API | REST/gRPC API endpoints | Error responses carry registered error codes with structured recovery hints |
| OPS-HEALTH | Health gate / readiness probes | Metrics use `franken.{plane}.*` namespace; errors carry canonical codes |
| OPS-DASH | Dashboard integrations | Consumed metrics enumerated in dashboard contract files |
| OPS-LOG | Structured log output | Log entries carry `trace_id`, `span_id`, and canonical error code refs |
| OPS-CONTROL | Control plane decisions | Evidence entries reference canonical error taxonomy |

## Event Codes

| Code | Trigger | Severity |
|------|---------|----------|
| SOB-001 | Non-canonical metric name detected in operational surface | WARN |
| SOB-002 | Error emitted without registered error code | WARN |
| SOB-003 | Structured log entry missing trace context fields | WARN |
| SOB-004 | Dashboard contract references metric not in canonical namespace | WARN |

## Invariants

- **INV-SOB-METRIC-CANONICAL** -- Every metric emitted by an operational surface
  uses a name from the canonical `SchemaRegistry`.  No ad-hoc or legacy metric
  names may appear in production code paths.  Violations emit SOB-001.

- **INV-SOB-ERROR-REGISTERED** -- Every user-facing or operator-facing error
  carries a registered error code from the `ErrorCodeRegistry`.  Each error
  includes associated severity, category, and machine-readable recovery hint
  conforming to the `RecoveryHint` schema.  Violations emit SOB-002.

- **INV-SOB-TRACE-CONTEXT** -- Structured log entries carry trace context
  fields (`trace_id`, `span_id`) and reference canonical error codes where
  applicable, enabling end-to-end correlation.  Missing context emits SOB-003.

- **INV-SOB-DASHBOARD-VALID** -- Dashboard contract files enumerate consumed
  metrics per integration surface.  Every referenced metric must exist in the
  canonical namespace.  Stale references emit SOB-004.

## Canonical Namespace Prefixes

All emitted metrics must use one of the four canonical plane prefixes defined by
the upstream telemetry namespace contract (bd-1ugy):

| Plane | Prefix |
|-------|--------|
| Protocol | `franken.protocol.` |
| Capability | `franken.capability.` |
| Egress | `franken.egress.` |
| Security | `franken.security.` |

Any metric name not starting with one of these prefixes is a compliance
violation (SOB-001).

## Recovery Hint Schema

Recovery hints must be structured JSON objects parseable by autonomous operator
agents.  The canonical schema:

```json
{
  "action": "<enum: retry | escalate | reconfigure | rollback | ignore>",
  "target": "<resource identifier string>",
  "confidence": 0.85,
  "escalation_path": "optional: on-call-sre | platform-team"
}
```

Fields:
- `action` (required, enum) -- The recommended remediation action.
- `target` (required, string) -- The resource or subsystem to act on.
- `confidence` (required, float 0-1) -- Confidence in the recovery suggestion.
- `escalation_path` (optional, string) -- Human escalation target if automated
  recovery is insufficient.

## Backward Compatibility

Removing or renaming a canonical metric or error code requires a deprecation
cycle of at least one release with both old and new names active.  The
`SchemaRegistry` enforces this via its `INV-TNS-DEPRECATED` invariant and the
`ErrorCodeRegistry` via `INV-ECR-FROZEN`.

## Adoption Checklist

1. CLI structured JSON output validates against canonical schemas.
2. API error responses include registered error codes with recovery hints.
3. Health gate metrics use `franken.{plane}.*` namespace prefixes.
4. Dashboard contract files enumerate all consumed metrics.
5. Structured logs include `trace_id` and `span_id` fields.
6. Control evidence entries reference canonical error codes.
7. No ad-hoc metric names in production code paths.

## Dependencies

- bd-1ugy: Stable telemetry namespace (10.13)
- bd-novi: Stable error code namespace (10.13)
- bd-3tzl: Trace context propagation (trace_context.rs)
- cli.rs: CLI structured output infrastructure

## Verification

Compliance audit via `scripts/check_structured_observability.py` scans all
operational surface source files and contract documents.  Zero violations
required for gate passage.
