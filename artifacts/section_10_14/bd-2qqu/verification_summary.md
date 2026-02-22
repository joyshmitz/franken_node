# bd-2qqu -- Virtual Transport Fault Harness -- Verification Summary

**Section:** 10.14 -- Remote Capabilities & Protocol Testing
**Verdict:** PASS (10/10 gate checks)

## Evidence

| Metric | Value |
|--------|-------|
| Gate checks | 10/10 PASS |
| Rust inline tests | 19 |
| Python unit tests | 36/36 PASS |
| Event codes | 12 (FAULT_*) |
| Invariants | 6 verified |
| Fault classes | 3 (Drop, Reorder, Corrupt) |
| Pre-built scenarios | 5 |
| Core types | 8 |

## Gate Checks

| Check | Status | Detail |
|-------|--------|--------|
| SOURCE_EXISTS | PASS | virtual_transport_faults.rs present |
| EVENT_CODES | PASS | 12/12 event codes |
| INVARIANTS | PASS | 6/6 invariants |
| CORE_TYPES | PASS | 5/5 types |
| PREBUILT_SCENARIOS | PASS | 5/5 scenarios |
| DETERMINISTIC_SCHEDULE | PASS | seed-based deterministic schedule |
| FAULT_INJECTION | PASS | 3 fault injection methods |
| CAMPAIGN_RUNNER | PASS | campaign execution |
| AUDIT_TRAIL | PASS | log export |
| TEST_COVERAGE | PASS | 19 tests found |

## Artifacts

- Implementation: `crates/franken-node/src/remote/virtual_transport_faults.rs` (604 lines)
- Spec contract: `docs/specs/section_10_14/bd-2qqu_contract.md`
- Verification script: `scripts/check_virtual_transport_faults.py` (10 checks)
- Unit tests: `tests/test_check_virtual_transport_faults.py` (36 tests)

## Key Capabilities

- Three fault classes: Drop (silent discard), Reorder (depth-bounded delayed delivery), Corrupt (bit-flip)
- Seed-driven deterministic PRNG (xorshift64) for reproducible fault schedules
- Five pre-built scenarios: no_faults, moderate_drops, heavy_reorder, light_corruption, chaos
- Reorder buffer with depth-controlled delayed delivery and flush
- Bit-level corruption with configurable bit positions
- Campaign execution with SHA-256 deterministic content hashing
- FaultConfig validation with probability bounds and budget checking
- JSONL export for both fault log and audit log
- 12 structured event codes in `event_codes` module
- 6 invariants in `invariants` module
