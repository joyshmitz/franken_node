# bd-206h: Idempotency Dedupe Store -- Verification Summary

**Section:** 10.14 | **Bead:** bd-206h | **Date:** 2026-02-21

## Gate Result: PASS

| Metric | Value |
|--------|-------|
| Rust in-module tests | 20 |
| Event codes | 7 (ID_ENTRY_NEW..ID_SWEEP_COMPLETE) |
| Invariants | 5 verified (INV-IDS-*) |
| Schema version | ids-v1.0 |
| Default TTL | 604800 seconds (7 days) |

## Implementation

- `crates/franken-node/src/remote/idempotency_store.rs` -- Dedupe store
- `crates/franken-node/src/remote/mod.rs` -- Module registration
- `docs/specs/section_10_14/bd-206h_contract.md` -- Spec contract
- `scripts/check_idempotency_store.py` -- Verification gate
- `tests/test_check_idempotency_store.py` -- Python test suite

## Key Capabilities

- At-most-once execution via check_or_insert (New/Duplicate/Conflict/InFlight)
- Same-key different-payload hard-fail (ERR_IDEMPOTENCY_CONFLICT)
- TTL-based expiration (default 7 days) with sweep_expired
- Crash recovery: recover_inflight marks Processing entries as Abandoned
- Abandoned entries allow retry (return New on re-check)
- Deterministic content_hash over ordered BTreeMap
- JSONL audit log export (schema ids-v1.0)
- Stats counters (new, duplicate, conflict, expired)
