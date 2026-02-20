# bd-3b8m: Anti-Amplification Response Bounds

## Purpose

Prevent amplification attacks in retrieval/sync traffic. Response payloads never exceed request-declared bounds. Unauthenticated peers get stricter limits. Adversarial traffic harness reproduces attacks deterministically.

## Invariants

- **INV-AAR-BOUNDED**: Response size never exceeds the declared bound from the request, even under adversarial inputs.
- **INV-AAR-UNAUTH-STRICT**: Unauthenticated peers have strictly lower response bounds than authenticated peers.
- **INV-AAR-AUDITABLE**: Every bound check emits a structured record with request_id, peer_id, bound, actual, verdict.
- **INV-AAR-DETERMINISTIC**: Same request + same policy → same bound enforcement decision.

## Types

### AmplificationPolicy

Global policy: max_response_ratio, unauth_max_bytes, auth_max_bytes, max_items_per_response.

### ResponseBound

Per-request declared bound: max_bytes, max_items.

### BoundCheckRequest

Request to check: request_id, peer_id, authenticated, declared_bound, actual_response_bytes, actual_items.

### BoundCheckVerdict

Result: request_id, allowed, violations, enforced_limit, trace_id.

### AmplificationAuditEntry

Audit record: request_id, peer_id, timestamp, declared_bound, actual_bytes, enforced_limit, ratio, verdict.

## Error Codes

- `AAR_RESPONSE_TOO_LARGE` — response exceeds declared bound
- `AAR_RATIO_EXCEEDED` — response/request ratio exceeds policy
- `AAR_UNAUTH_LIMIT` — unauthenticated peer exceeded strict limit
- `AAR_ITEMS_EXCEEDED` — response items exceed per-response cap
- `AAR_INVALID_POLICY` — policy configuration is invalid
