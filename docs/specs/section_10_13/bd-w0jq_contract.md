# bd-w0jq: Degraded-Mode Audit Events for Stale Revocation Overrides

## Bead: bd-w0jq | Section: 10.13

## Purpose

Emits explicit degraded-mode audit events whenever a stale revocation
frontier override is used. Every override produces a structured audit
event with required schema fields. Missing events are hard failures
in conformance tests. Events correlate to action IDs and trace IDs.

## Invariants

| ID | Statement |
|----|-----------|
| INV-DM-EVENT-REQUIRED | Every stale-frontier override MUST emit a degraded-mode audit event; missing events are failures. |
| INV-DM-SCHEMA-COMPLETE | Each event contains all required fields: event_type, action_id, actor, tier, revocation_age_secs, max_age_secs, override_reason, trace_id, timestamp. |
| INV-DM-CORRELATION | Events correlate to action_id and trace_id of the originating freshness check. |
| INV-DM-IMMUTABLE | Once emitted, events cannot be modified or deleted from the audit log. |

## Types

### DegradedModeEvent
- `event_type: String` — always `"degraded_mode_override"`.
- `action_id: String`
- `actor: String`
- `tier: String`
- `revocation_age_secs: u64`
- `max_age_secs: u64`
- `override_reason: String`
- `trace_id: String`
- `timestamp: String`

### DegradedModeAuditLog
- Append-only log of `DegradedModeEvent`.
- Methods: `emit`, `find_by_action`, `find_by_trace`, `validate_schema`, `count`.

### AuditError
- `MissingField { field }` — required field is empty.
- `EventNotFound { action_id }` — expected event not in log.
- `SchemaViolation { reason }` — event fails schema validation.

## Error Codes

| Code | Trigger |
|------|---------|
| `DM_MISSING_FIELD` | A required audit field is empty or absent. |
| `DM_EVENT_NOT_FOUND` | Expected degraded-mode event not found in log. |
| `DM_SCHEMA_VIOLATION` | Event fails structured schema validation. |

## Expected Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_13/bd-w0jq_contract.md` |
| Implementation | `crates/franken-node/src/security/degraded_mode_audit.rs` |
| Conformance tests | `tests/conformance/degraded_mode_audit_events.rs` |
| Degraded mode events | `artifacts/section_10_13/bd-w0jq/degraded_mode_events.jsonl` |
| Verification evidence | `artifacts/section_10_13/bd-w0jq/verification_evidence.json` |
| Verification summary | `artifacts/section_10_13/bd-w0jq/verification_summary.md` |
