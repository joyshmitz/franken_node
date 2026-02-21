# Structured Observability Policy

## Purpose

This policy governs the adoption and enforcement of canonical structured
observability contracts across all operational surfaces of franken_node.  It
ensures uniform metric naming, stable error taxonomy, and end-to-end trace
correlation so that operators (both human and autonomous) can triage issues
without encountering ad-hoc naming or opaque error codes.

## Canonical Log Format

All structured log entries emitted by franken_node operational surfaces MUST
conform to the following canonical format:

```json
{
  "timestamp": "2026-02-20T12:00:00.000Z",
  "level": "error|warn|info|debug",
  "message": "Human-readable description",
  "trace_id": "32-hex-char trace identifier",
  "span_id": "16-hex-char span identifier",
  "error_code": "FRANKEN_{SUBSYSTEM}_{CODE}",
  "surface": "OPS-CLI|OPS-API|OPS-HEALTH|OPS-DASH|OPS-LOG|OPS-CONTROL",
  "metric_refs": ["franken.protocol.messages_received_total"],
  "recovery_hint": {
    "action": "retry|escalate|reconfigure|rollback|ignore",
    "target": "resource-identifier",
    "confidence": 0.85,
    "escalation_path": "optional-escalation-target"
  }
}
```

Fields `trace_id` and `span_id` are REQUIRED on all entries at `warn` level and
above.  The `error_code` field is REQUIRED whenever the entry describes an error
condition.

## Error Taxonomy

### Error Code Format

All error codes follow the pattern `FRANKEN_{SUBSYSTEM}_{CODE}` as defined by
the bd-novi error code registry contract (10.13).

### Severity Levels

| Severity | Meaning | Recovery expectation |
|----------|---------|---------------------|
| Fatal | Unrecoverable -- process should terminate or escalate | `retryable=false` |
| Degraded | Degraded but functional -- operator should investigate | `retryable=true` or `false` |
| Transient | Temporary condition -- automatic retry appropriate | `retryable=true`, `retry_after_ms` set |

### Recovery Hints

Every non-fatal error MUST include a structured recovery hint with:

- `action` (enum): `retry`, `escalate`, `reconfigure`, `rollback`, `ignore`
- `target` (string): The specific resource or subsystem identifier
- `confidence` (float 0-1): Confidence in the suggested recovery
- `escalation_path` (optional string): Human escalation target

Recovery hints MUST be structured JSON objects -- not free-text -- so that
autonomous operator agents can parse and act on them without NLP.

### Trace IDs

Trace context follows the W3C Trace Context specification format:
- `trace_id`: 32 lowercase hexadecimal characters
- `span_id`: 16 lowercase hexadecimal characters
- `parent_span_id`: optional, 16 lowercase hexadecimal characters

All high-impact control flows MUST propagate trace context.  Missing trace
context on a WARN-level or higher log entry is a conformance violation (SOB-003).

## Operational Surface Inventory

| Surface ID | Description | Metric namespace | Error code scope |
|------------|-------------|-----------------|-----------------|
| OPS-CLI | CLI commands with `--json` output | `franken.protocol.*`, `franken.capability.*` | All FRANKEN_* codes |
| OPS-API | REST/gRPC API endpoints | `franken.protocol.*`, `franken.egress.*` | All FRANKEN_* codes |
| OPS-HEALTH | Health gate and readiness probes | `franken.protocol.*`, `franken.security.*` | FRANKEN_PROTOCOL_*, FRANKEN_SECURITY_* |
| OPS-DASH | Dashboard integration surfaces | All planes | N/A (read-only consumer) |
| OPS-LOG | Structured log output | All planes | All FRANKEN_* codes |
| OPS-CONTROL | Control plane decision evidence | `franken.security.*`, `franken.protocol.*` | FRANKEN_PROTOCOL_*, FRANKEN_SECURITY_* |

## Adoption Checklist

- [ ] All CLI commands emitting operational state support `--json` flag
- [ ] CLI JSON output uses canonical metric names from SchemaRegistry
- [ ] API error responses carry registered ErrorCodeEntry codes
- [ ] API error responses include structured RecoveryInfo
- [ ] Health gate metrics use `franken.{plane}.*` namespace prefixes
- [ ] Dashboard contract files enumerate consumed canonical metrics
- [ ] Structured logs include `trace_id` and `span_id` at WARN+ level
- [ ] Structured logs reference canonical error codes for error conditions
- [ ] Control evidence entries reference canonical error taxonomy
- [ ] No ad-hoc or legacy metric names in production code paths
- [ ] Deprecation cycles enforced for metric/error code changes

## Enforcement

### SOB Event Codes

| Code | Trigger | Action |
|------|---------|--------|
| SOB-001 | Non-canonical metric name in operational surface | Block deployment; fix metric name |
| SOB-002 | Error without registered error code | Block deployment; register code |
| SOB-003 | Log entry missing trace context at WARN+ level | Warn; require fix before next release |
| SOB-004 | Dashboard references non-existent canonical metric | Warn; update dashboard contract |

### INV Invariants

| Invariant | Description |
|-----------|-------------|
| INV-SOB-METRIC-CANONICAL | All emitted metrics use canonical SchemaRegistry names |
| INV-SOB-ERROR-REGISTERED | All errors carry registered ErrorCodeRegistry codes |
| INV-SOB-TRACE-CONTEXT | Structured logs carry trace context fields |
| INV-SOB-DASHBOARD-VALID | Dashboard contracts reference only valid canonical metrics |

### Deprecation Cycle

Per the upstream telemetry namespace (INV-TNS-DEPRECATED) and error code
registry (INV-ECR-FROZEN) contracts:

1. A metric or error code marked for removal enters a "deprecated" state.
2. During the deprecation window (minimum one full release cycle), both old and
   new identifiers are active.
3. Dashboard contracts and operational surfaces must migrate to the new
   identifier before the old one is removed.
4. Removal of a deprecated identifier requires explicit approval and triggers
   SOB-001 or SOB-002 if any surface still references it.

## Governance

Changes to this policy require review by the observability owner track (10.8)
and approval from the platform engineering lead.  Emergency exceptions may be
granted with a documented waiver that includes a remediation timeline.
