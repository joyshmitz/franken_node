# bd-f2y -- Incident Bundle Retention and Export Policy

## Overview

Section 9I.16 mandates classification of control-plane artifacts into retention
classes with enforceable policies.  Without a formal retention system, incident
bundles accumulate without bound (causing storage pressure) or are prematurely
deleted (destroying compliance evidence).  This bead implements the retention
policy engine that classifies, stores, rotates, and exports incident bundles
according to configurable, auditable policies.

The upstream 10.13 chain delivered the foundational retention infrastructure
(bd-1p2b: `retention_policy.rs`) with `RetentionClass`, `RetentionPolicy`,
`RetentionRegistry`, and `RetentionStore`.  This bead builds the **incident
bundle** layer on top: structured bundle format, tiered retention periods,
multi-format export, and automated cleanup.

## Bundle Format

An incident bundle is a structured JSON document containing:

```json
{
  "bundle_id": "ibr-<sha256-prefix>",
  "incident_id": "INC-2026-001",
  "created_at": "2026-02-20T12:00:00.000000Z",
  "severity": "critical",
  "retention_tier": "hot",
  "metadata": {
    "title": "Authentication service degradation",
    "detected_by": "health_gate",
    "component_ids": ["auth-svc-01", "auth-svc-02"],
    "tags": ["security", "availability"]
  },
  "logs": [...],
  "traces": [...],
  "metrics_snapshots": [...],
  "evidence_refs": [...],
  "export_format_version": 1,
  "integrity_hash": "<sha256>"
}
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `bundle_id` | string | Unique identifier, format `ibr-<hash-prefix>` |
| `incident_id` | string | Parent incident identifier |
| `created_at` | string | RFC 3339 creation timestamp |
| `severity` | enum | `critical`, `high`, `medium`, `low` |
| `retention_tier` | enum | `hot`, `cold`, `archive` |
| `metadata` | object | Incident metadata (title, detector, components, tags) |
| `logs` | array | Structured log entries from incident window |
| `traces` | array | Trace spans from incident window |
| `metrics_snapshots` | array | Metric snapshots at key incident moments |
| `evidence_refs` | array | References to evidence ledger entries |
| `export_format_version` | integer | Schema version for forward compatibility |
| `integrity_hash` | string | SHA-256 hash of all fields except itself |

## Retention Periods

Incident bundles follow a tiered retention model with configurable periods:

| Tier | Default Period | Storage Class | Auto-Transition |
|------|---------------|---------------|-----------------|
| Hot | 90 days | Fast local storage | Moves to cold after period |
| Cold | 1 year (365 days) | Compressed storage | Moves to archive after period |
| Archive | 7 years (2555 days) | Compliance archive | Requires explicit deletion |

### Retention Rules

1. **Hot tier**: Active incident bundles for ongoing investigation and operations.
   Bundles are stored uncompressed for fast access.  After 90 days, bundles
   transition to cold tier automatically.

2. **Cold tier**: Bundles no longer under active investigation but needed for
   trend analysis and audit.  Stored compressed.  After 1 year, bundles
   transition to archive tier.

3. **Archive tier**: Long-term compliance retention.  Bundles are immutable.
   Deletion requires explicit operator action with audit trail.  Minimum
   retention: 7 years per regulatory requirement.

### Configuration

Retention periods are configurable per deployment via `config.rs`:

```toml
[retention.incident_bundles]
hot_days = 90
cold_days = 365
archive_days = 2555
cleanup_interval_hours = 1
storage_warn_percent = 70
storage_critical_percent = 85
```

## Export Formats

Incident bundles can be exported in three formats:

| Format | Extension | Use Case |
|--------|-----------|----------|
| JSON | `.json` | General interchange, API consumption |
| CSV | `.csv` | Spreadsheet analysis, tabular reporting |
| SARIF | `.sarif` | Security incident integration with SAST/DAST tooling |

### JSON Export

Full-fidelity export preserving all bundle fields.  Includes integrity hash
for verification on import.

### CSV Export

Flattened tabular format with columns: `bundle_id`, `incident_id`, `created_at`,
`severity`, `retention_tier`, `title`, `detected_by`, `component_count`,
`log_count`, `trace_count`, `metric_snapshot_count`.

### SARIF Export

Security-focused export conforming to SARIF v2.1.0 schema.  Maps incident
metadata to SARIF `run`, `result`, and `location` objects.  Used for security
incidents that need integration with security scanning pipelines.

## Event Codes

| Code | Trigger | Severity |
|------|---------|----------|
| IBR-001 | Incident bundle created and classified | INFO |
| IBR-002 | Retention period expired, tier transition triggered | INFO |
| IBR-003 | Export requested (any format) | INFO |
| IBR-004 | Automated cleanup executed (ephemeral artifacts removed) | INFO |

## Invariants

- **INV-IBR-COMPLETE** -- Every incident bundle contains all required fields
  (metadata, logs, traces, metrics_snapshots, evidence_refs).  No bundle may
  be stored with missing required sections.  Violations are rejected at
  creation time.

- **INV-IBR-RETENTION** -- Retention tier transitions follow the configured
  schedule.  Hot bundles move to cold after the hot period; cold bundles move
  to archive after the cold period.  Archive bundles are never automatically
  deleted.  Every transition emits IBR-002.

- **INV-IBR-EXPORT** -- Exported bundles include an integrity hash computed
  over all content fields.  Re-importing an exported bundle and recomputing
  the hash must produce an identical value.  Format-specific exports (CSV,
  SARIF) are derived deterministically from the canonical JSON representation.

- **INV-IBR-INTEGRITY** -- The integrity_hash field is a SHA-256 digest of
  the canonical JSON representation of all other fields.  Any modification
  to bundle content invalidates the hash.  Integrity is verified on every
  read and export operation.

## Automated Cleanup and Rotation

The retention sweeper runs on a configurable schedule (default: hourly):

1. **Tier rotation**: Scans all bundles and transitions those past their
   retention period to the next tier.  Emits IBR-002 for each transition.

2. **Ephemeral cleanup**: Removes expired ephemeral artifacts (health pings,
   status polls) per the upstream retention_policy.rs classification.  Emits
   IBR-004 for each cleanup batch.

3. **Capacity monitoring**: When storage utilization crosses thresholds
   (70% warn, 85% critical), structured alerts are emitted identifying the
   largest bundle categories and recommended actions.

4. **Archive integrity**: Periodically verifies integrity hashes of archive-tier
   bundles.  Hash mismatches trigger immediate alerts.

## Acceptance Criteria

1. All incident bundles are automatically classified with a retention tier
   at creation time based on severity and artifact type.
2. Retention periods are configurable per deployment; defaults match this spec.
3. Tier transitions happen automatically on schedule and emit IBR-002 events.
4. Archive-tier bundles are never automatically deleted.
5. Export produces valid output in all three formats (JSON, CSV, SARIF) with
   integrity verification.
6. Re-import of exported JSON bundles passes integrity hash verification.
7. Automated cleanup removes only expired ephemeral artifacts and emits IBR-004.
8. Every retention decision is logged as an auditable event.
9. Capacity alerts fire at configured thresholds with structured output.
10. A verification script validates all current bundles have valid classifications.

## Dependencies

- bd-1p2b: Control-plane retention policy (10.13, `retention_policy.rs`)
- bd-vll: Deterministic incident replay bundle (10.5, `replay_bundle.rs`)
- config.rs: Configuration system for retention period tuning
- health_gate.rs: Capacity alert integration

## Verification

Compliance audit via `scripts/check_incident_bundles.py` validates all
contract elements.  Zero violations required for gate passage.
