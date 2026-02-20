# bd-3cm3: Schema-Gated Quarantine Promotion

## Purpose

Promotion from quarantine requires reachability, authenticated request, and schema validation. Every promotion emits a provenance receipt with promotion reason. Invalid promotions fail closed.

## Invariants

- **INV-QPR-SCHEMA-GATED**: Promotion requires passing schema validation; objects failing validation remain quarantined.
- **INV-QPR-AUTHENTICATED**: Promotion requests must be authenticated; unauthenticated promotions are rejected.
- **INV-QPR-RECEIPT**: Every successful promotion emits a provenance receipt with reason, validator, timestamp.
- **INV-QPR-FAIL-CLOSED**: Any validation error causes promotion to fail closed (object stays quarantined).

## Types

### PromotionRule

Rule for promotion: required_schema_version, require_reachability, require_pin.

### PromotionRequest

Request to promote: object_id, requester_id, authenticated, schema_version, reachable, pinned, reason.

### ProvenanceReceipt

Audit receipt: object_id, promoted_at, requester_id, reason, schema_version, validator_id, trace_id.

### PromotionResult

Outcome: object_id, promoted (bool), receipt (if promoted), rejection_reasons.

## Error Codes

- `QPR_SCHEMA_FAILED` — object failed schema validation
- `QPR_NOT_AUTHENTICATED` — promotion request not authenticated
- `QPR_NOT_REACHABLE` — object not reachable (orphaned)
- `QPR_NOT_PINNED` — object not pinned when pin required
- `QPR_INVALID_RULE` — promotion rule configuration invalid
