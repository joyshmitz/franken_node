# bd-1vsr — Transition Abort Semantics — Verification Summary

**Section:** 10.14 — Remote Capabilities & Protocol Testing
**Verdict:** PASS (29/29 gate checks)

## Evidence

| Metric | Value |
|--------|-------|
| Gate checks | 29/29 PASS |
| Rust inline tests | 23 |
| Python unit tests | 37/37 PASS |
| Event codes | 10 (TRANSITION_ABORTED, FORCE_TRANSITION_APPLIED, ...) |
| Error codes | 8 (ERR_ABORT_*, ERR_FORCE_*) |
| Invariants | 6 verified |
| Abort reasons | 3 (Timeout, Cancellation, ParticipantFailure) |

## Implementation

- `crates/franken-node/src/control_plane/transition_abort.rs` — Core abort semantics
- `crates/franken-node/src/control_plane/mod.rs` — Module registration
- `docs/specs/section_10_14/bd-1vsr_contract.md` — Spec contract
- `scripts/check_transition_abort.py` — Verification gate (29 checks)
- `tests/test_check_transition_abort.py` — Python test suite (37 tests)

## Key Capabilities

- Default abort on timeout/cancellation: system remains at pre-transition epoch
- ForceTransitionPolicy for explicit, scoped overrides
- Force policy requires operator identity and audit reason (no default)
- Force policy bounded: skipped participants cannot exceed max_skippable
- Force policy scoped: names specific skippable participants
- Partial state detection via verify_no_partial_state()
- Deterministic policy hashing for audit trails
- JSONL audit log export with abort/force events
