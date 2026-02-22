# bd-1cwp: Control-Plane Idempotency Key Enforcement

**Section:** 10.15 | **Type:** task | **Priority:** P1

## Overview

Enforces canonical idempotency-key contracts from Section 10.14 on all
retryable remote control requests. Ensures at-most-once semantics via
canonical key derivation (bd-12n3) and dedupe store (bd-206h).

## Retryable Requests (4 of 5)

| Request | Key Derivation | Dedup |
|---------|---------------|-------|
| health_probe | canonical | yes |
| rollout_notify | canonical | yes |
| migration_step | canonical | yes |
| sync_delta | canonical | yes |

`fencing_acquire` is non-retryable (fail-fast).

## Invariants

| ID | Rule |
|----|------|
| INV-IDP-CANONICAL-KEY | Keys derived via canonical function |
| INV-IDP-DEDUP-CONSULTED | Dedupe store consulted before dispatch |
| INV-IDP-EPOCH-BOUND | Keys scoped to epoch |
| INV-IDP-NO-CUSTOM | No custom idempotency in product modules |
| INV-IDP-CONFLICT-HARD | Key/payload mismatch is hard error |

## Artifacts

- `docs/integration/control_idempotency_adoption.md`
- `artifacts/10.15/control_idempotency_report.json`
- `docs/specs/section_10_15/bd-1cwp_contract.md`
- `scripts/check_control_idempotency_adoption.py`
- `tests/test_check_control_idempotency_adoption.py`
- `artifacts/section_10_15/bd-1cwp/verification_evidence.json`
- `artifacts/section_10_15/bd-1cwp/verification_summary.md`
