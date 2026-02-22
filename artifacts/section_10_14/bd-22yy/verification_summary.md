# bd-22yy — DPOR-Style Schedule Exploration Gates — Verification Summary

**Section:** 10.14 — Remote Capabilities & Protocol Testing
**Verdict:** PASS (33/33 gate checks)

## Evidence

| Metric | Value |
|--------|-------|
| Gate checks | 33/33 PASS |
| Rust inline tests | 22 |
| Python unit tests | 41/41 PASS |
| Event codes | 10 (DPOR_*) |
| Error codes | 8 (ERR_DPOR_*) |
| Invariants | 6 verified |
| Protocol models | 3 |

## Implementation

- `crates/franken-node/src/control_plane/dpor_exploration.rs` — Core DPOR framework
- `crates/franken-node/src/control_plane/mod.rs` — Module registration
- `docs/specs/section_10_14/bd-22yy_contract.md` — Spec contract
- `scripts/check_dpor_exploration.py` — Verification gate (33 checks)
- `tests/test_check_dpor_exploration.py` — Python test suite (41 tests)

## Key Capabilities

- 3 protocol models: epoch barrier, remote capability, marker stream
- Topological linearization with dependency-respecting schedule generation
- Safety property checking at each explored state
- Counterexample traces with step-by-step operation ordering
- Budget enforcement (time + memory)
- Coverage metrics (explored/estimated percentage)
- Model validation (empty, no properties, unknown deps)
- JSONL audit log export
