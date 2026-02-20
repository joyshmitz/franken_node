# bd-3b8m: Anti-Amplification Response Bounds — Verification Summary

## Verdict: PASS (6/6 checks)

## Implementation

`crates/franken-node/src/connector/anti_amplification.rs`

- `AmplificationPolicy`: configurable ratio, auth/unauth byte caps, max items per response
- `check_response_bound()`: evaluates 4 checks (size vs declared bound, ratio, unauth limit, items)
- `enforced_limit()`: minimum of declared bound and auth-appropriate cap (INV-AAR-UNAUTH-STRICT)
- `run_adversarial_harness()`: batch processing for deterministic adversarial replay
- Rejected requests produce audit entries with full context

## Invariants Verified

| Invariant | Status | Evidence |
|-----------|--------|----------|
| INV-AAR-BOUNDED | PASS | Response exceeding declared bound always blocked (21 unit tests, integration test) |
| INV-AAR-UNAUTH-STRICT | PASS | Unauth cap < auth cap enforced by policy validation + limit computation |
| INV-AAR-AUDITABLE | PASS | AmplificationAuditEntry per check with request_id, peer_id, timestamp, ratio, verdict |
| INV-AAR-DETERMINISTIC | PASS | Same request + policy → same verdict (unit + integration test) |

## Error Codes

All 5 error codes present: AAR_RESPONSE_TOO_LARGE, AAR_RATIO_EXCEEDED, AAR_UNAUTH_LIMIT, AAR_ITEMS_EXCEEDED, AAR_INVALID_POLICY.

## Test Results

- 21 Rust unit tests passed
- 4 integration tests (1 per invariant)
- 16 Python verification tests passed
- Adversarial harness fixture with 6 scenarios
