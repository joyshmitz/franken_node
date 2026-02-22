# bd-1n5p Verification Summary: Obligation-Tracked Two-Phase Channels

**Bead:** bd-1n5p
**Section:** 10.15
**Verdict:** PASS
**Date:** 2026-02-22

## Overview

This bead replaces ad hoc fire-and-forget messaging in publish, revoke, quarantine,
migration, and fencing flows with obligation-tracked two-phase channels. Every
side-effecting operation goes through reserve/commit/rollback semantics with a
periodic leak oracle that detects and force-rolls-back orphaned obligations.

## Implementation

- **File:** `crates/franken-node/src/connector/obligation_tracker.rs`
- **Module:** Registered in `connector/mod.rs`
- **Schema version:** obl-v1.0

## Verification Results

| Check                | Status | Details                                          |
|----------------------|--------|--------------------------------------------------|
| SOURCE_EXISTS        | PASS   | obligation_tracker.rs present in connector       |
| EVENT_CODES          | PASS   | 5 codes: OBL-001 through OBL-005                |
| INVARIANTS           | PASS   | 6 invariants defined and enforced                |
| ERROR_CODES          | PASS   | 5 error codes defined                            |
| CORE_TYPES           | PASS   | 8 types: ObligationTracker, Obligation, etc.     |
| TRACKED_FLOWS        | PASS   | 5 flows: publish, revoke, quarantine, migration, fencing |
| REQUIRED_METHODS     | PASS   | 10 methods implemented                           |
| SCHEMA_VERSION       | PASS   | obl-v1.0 declared                                |
| SERDE_DERIVES        | PASS   | Serialize/Deserialize present                    |
| TEST_COVERAGE        | PASS   | 32 Rust unit tests (>= 15 required)             |
| MODULE_REGISTERED    | PASS   | obligation_tracker in connector/mod.rs           |
| SPEC_EXISTS          | PASS   | Contract spec at section_10_15/bd-1n5p           |
| TWO_PHASE_SPEC       | PASS   | Two-phase effects spec at two_phase_effects.md   |
| ORACLE_REPORT        | PASS   | Leak oracle report with PASS verdict             |

## Key Design Decisions

1. **Reserve/Commit/Rollback protocol:** Every critical side-effect is first
   reserved (creating a tracked obligation), then committed (fulfilling it),
   or rolled back (releasing tentative resources).
2. **Leak oracle:** A periodic scan detects obligations stuck in Reserved state
   beyond a configurable timeout, force-rolling them back and emitting OBL-004
   events. The scan itself emits OBL-005.
3. **Idempotent rollback:** Rolling back an already-rolled-back obligation is
   a safe no-op (INV-OBL-ROLLBACK-SAFE).
4. **Audit completeness:** Every lifecycle transition emits an ObligationAuditRecord
   with event code, flow, state, and trace ID (INV-OBL-AUDIT-COMPLETE).
5. **All five flows tracked:** Publish, Revoke, Quarantine, Migration, and
   Fencing are all represented as ObligationFlow variants.

## Test Coverage

- 32 Rust unit tests covering all invariants, state transitions,
  leak detection, audit logging, flow lifecycle, and error conditions.
- Python verification script with self-test mode.
- Python unit test suite for the verification script.
