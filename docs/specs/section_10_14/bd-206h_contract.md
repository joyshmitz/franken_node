# bd-206h Contract: Idempotency Dedupe Store

## Overview

The idempotency dedupe store provides at-most-once execution semantics for
retryable remote-control requests.  It tracks idempotency keys (derived by
bd-12n3) and their outcomes.  Same key + same payload returns a cached result;
same key + different payload hard-fails with a conflict error.

## Data Model

### EntryStatus

Three-state lifecycle enum:

| Variant      | Meaning                                        |
|--------------|------------------------------------------------|
| `Processing` | Operation in-flight, not yet completed         |
| `Complete`   | Outcome cached, entry returns `Duplicate`      |
| `Abandoned`  | Crash recovery resolved an in-flight entry     |

### CachedOutcome

| Field              | Type       | Description                       |
|--------------------|------------|-----------------------------------|
| `result_hash`      | `String`   | SHA-256 hex of `result_data`      |
| `result_data`      | `Vec<u8>`  | Serialised result bytes           |
| `completed_at_secs`| `u64`      | Completion timestamp (epoch secs) |

### DedupeEntry

| Field            | Type                  | Description                  |
|------------------|-----------------------|------------------------------|
| `key`            | `IdempotencyKey`      | From bd-12n3 derivation      |
| `payload_hash`   | `String`              | SHA-256 hex of request       |
| `status`         | `EntryStatus`         | Current lifecycle status     |
| `outcome`        | `Option<CachedOutcome>`| Cached result when Complete |
| `created_at_secs`| `u64`                 | Creation timestamp           |
| `ttl_secs`       | `u64`                 | Time-to-live in seconds      |

### DedupeResult

| Variant     | Fields                                    | Meaning                                  |
|-------------|-------------------------------------------|------------------------------------------|
| `New`       | none                                      | First time seeing this key; proceed      |
| `Duplicate` | `CachedOutcome`                           | Same key + same payload; cached outcome  |
| `Conflict`  | `key_hex`, `expected_hash`, `actual_hash` | Same key + different payload; hard fail  |
| `InFlight`  | none                                      | Entry still processing                   |

### IdempotencyDedupeStore

Core store type backed by `BTreeMap<String, DedupeEntry>` for ordered,
deterministic iteration.

### IdsAuditRecord

Structured audit record with `event_code`, `trace_id`, and JSON `detail`.

## Invariants

| ID | Statement |
|----|-----------|
| INV-IDS-AT-MOST-ONCE | A completed entry's outcome is immutable |
| INV-IDS-CONFLICT-DETECT | Different payload for same key triggers ERR_IDEMPOTENCY_CONFLICT |
| INV-IDS-TTL-BOUND | Expired entries are treated as absent |
| INV-IDS-CRASH-SAFE | In-flight entries become Abandoned on recovery |
| INV-IDS-AUDITABLE | Every state transition emits a structured audit record |

## Event Codes (7)

ID_ENTRY_NEW, ID_ENTRY_DUPLICATE, ID_ENTRY_CONFLICT, ID_ENTRY_EXPIRED,
ID_STORE_RECOVERY, ID_INFLIGHT_RESOLVED, ID_SWEEP_COMPLETE

## Error Codes

ERR_IDEMPOTENCY_CONFLICT

## Operations

| Operation | Description |
|-----------|-------------|
| check_or_insert | Check key; return New/Duplicate/Conflict/InFlight |
| complete | Mark in-flight entry as complete with outcome |
| sweep_expired | Remove entries past TTL |
| recover_inflight | Mark Processing entries as Abandoned |
| export_audit_log_jsonl | Export audit log as JSONL |
| content_hash | Deterministic content hash over store entries |
| stats | Return (new, duplicate, conflict, expired) counters |

## Key Types

- `CachedOutcome` -- stored result hash, bytes, and completion timestamp
- `EntryStatus` -- Processing | Complete | Abandoned
- `DedupeEntry` -- key, payload hash, status, outcome, timestamps, TTL
- `DedupeResult` -- New | Duplicate(CachedOutcome) | Conflict{...} | InFlight
- `IdempotencyDedupeStore` -- the store itself
- `IdsAuditRecord` -- structured audit record

## Configuration Defaults

| Parameter | Default |
|-----------|---------|
| DEFAULT_TTL_SECS | 604,800 (7 days) |

## Schema Version

`ids-v1.0`

## Acceptance Criteria

1. `check_or_insert` returns `New` for unseen keys
2. `check_or_insert` returns `Duplicate(CachedOutcome)` for same key + same payload after `complete`
3. `check_or_insert` returns `Conflict` for same key + different payload
4. `check_or_insert` returns `InFlight` for an entry still Processing
5. Expired entries are treated as absent (INV-IDS-TTL-BOUND)
6. `sweep_expired` removes entries past their TTL
7. `recover_inflight` marks Processing entries as Abandoned
8. Abandoned entries allow retry (return New)
9. `content_hash` is deterministic across identical operations
10. `export_audit_log_jsonl` produces valid JSONL
11. `stats()` returns accurate counters
12. Default TTL is 604800 seconds (7 days)
13. At least 15 Rust unit tests covering all invariants

## Evidence Artifacts

- `crates/franken-node/src/remote/idempotency_store.rs`
- `scripts/check_idempotency_store.py`
- `tests/test_check_idempotency_store.py`
- `artifacts/section_10_14/bd-206h/verification_evidence.json`
- `artifacts/section_10_14/bd-206h/verification_summary.md`
