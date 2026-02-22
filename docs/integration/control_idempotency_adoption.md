# Control-Plane Idempotency Adoption

**Bead:** bd-1cwp | **Section:** 10.15

## Overview

This document defines how the canonical idempotency primitives from Section 10.14
are integrated into the control-plane layer. All retryable remote control requests
must carry idempotency keys derived via the canonical derivation function (bd-12n3)
and checked against the canonical dedupe store (bd-206h).

## Retryable Remote Requests

| Request Type | Domain | Idempotency Key Derivation | Retry Policy |
|---|---|---|---|
| `health_probe` | connector | `derive_key("health_probe", epoch, request_bytes)` | 2 retries, 1s backoff |
| `rollout_notify` | connector | `derive_key("rollout_notify", epoch, request_bytes)` | 1 retry, 2s backoff |
| `fencing_acquire` | connector | Not retryable (fail-fast) | No retry |
| `migration_step` | connector | `derive_key("migration_step", epoch, request_bytes)` | 3 retries, exponential |
| `sync_delta` | federation | `derive_key("sync_delta", epoch, request_bytes)` | 2 retries, 3s backoff |

Note: `fencing_acquire` is not retryable — it uses fail-fast semantics.
4 of 5 registered computations are retryable and require idempotency keys.

## Idempotency Key Derivation

All keys are derived using the canonical function from bd-12n3:

```
IdempotencyKeyDeriver::derive_key(computation_name, epoch, request_bytes)
```

- `computation_name`: the registered computation name (e.g., `connector.health_probe.v1`)
- `epoch`: the current control epoch at time of dispatch
- `request_bytes`: the serialized request payload

Keys are SHA-256 digests (32 bytes) with a domain prefix of `franken_node.idempotency.v1`.

## Dedupe Contract

The canonical dedupe store (bd-206h) enforces at-most-once semantics:

1. **Same key + same payload**: returns cached outcome (dedup hit). No duplicate side-effect.
2. **Same key + different payload**: returns hard conflict error (`ERR_IDEMPOTENCY_CONFLICT`).
3. **New key**: executes the request and commits the outcome to the store.

## Epoch Binding

Idempotency keys are epoch-bound:

- A key derived in epoch N is only valid in epoch N.
- After epoch transition to N+1, keys from epoch N are rejected with `ERR_EPOCH_MISMATCH`.
- This prevents replay attacks across epoch boundaries.

## Prohibition on Custom Idempotency Logic

No module under `crates/franken-node/src/connector/` or `crates/franken-node/src/federation/`
may implement custom idempotency logic:

- No custom key derivation (all keys must go through `IdempotencyKeyDeriver::derive_key`).
- No custom dedupe stores (all dedup checks must go through `IdempotencyDedupeStore`).
- This is enforced by automated scanning in the verification gate.

## Error Handling

| Error Code | Trigger | Recovery |
|---|---|---|
| `ERR_IDEMPOTENCY_CONFLICT` | Same key, different payload | Reject retry, alert caller |
| `ERR_EPOCH_MISMATCH` | Key from a different epoch | Reject, derive new key in current epoch |
| `ERR_KEY_DERIVATION_FAILED` | Canonical derivation failure | Fail request, do not dispatch |
| `ERR_DEDUP_STORE_UNAVAILABLE` | Dedupe store unreachable | Fail-closed, reject request |

## Invariants

| ID | Rule |
|----|------|
| INV-IDP-CANONICAL-KEY | All keys derived via canonical derivation function |
| INV-IDP-DEDUP-CONSULTED | Dedupe store consulted before every retryable dispatch |
| INV-IDP-EPOCH-BOUND | Keys are epoch-scoped, cross-epoch keys rejected |
| INV-IDP-NO-CUSTOM | No custom idempotency logic in product modules |
| INV-IDP-CONFLICT-HARD | Key/payload mismatch is a hard error, not silent |

## Structured Log Events

| Code | Description |
|------|-------------|
| IDP-001 | Idempotency key derived |
| IDP-002 | Dedup hit — cached result returned |
| IDP-003 | Conflict — key/payload mismatch |
| IDP-004 | Epoch-rejected key |
| IDP-005 | New request committed to dedupe store |
