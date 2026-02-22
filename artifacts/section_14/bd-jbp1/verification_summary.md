# bd-jbp1 — Replay Determinism Metrics — Verification Summary

**Section:** 14 — Benchmark & reporting
**Verdict:** PASS (19/19 gate checks)

## Evidence

| Metric | Value |
|--------|-------|
| Gate checks | 19/19 PASS |
| Rust inline tests | 23 |
| Python unit tests | 24/24 PASS |
| Event codes | 12 (RDM-001..RDM-010, RDM-ERR-001..RDM-ERR-002) |
| Invariants | 6 verified |
| Artifact categories | 5 |

## Implementation

- `crates/franken-node/src/tools/replay_determinism_metrics.rs` — Core engine
- `crates/franken-node/src/tools/mod.rs` — Module registration
- `docs/specs/section_14/bd-jbp1_contract.md` — Spec contract
- `scripts/check_replay_determinism_metrics.py` — Verification gate (19 checks)
- `tests/test_check_replay_determinism_metrics.py` — Python test suite (24 tests)

## Key Capabilities

- Hash-based output comparison across replay runs
- Divergence severity classification (None/Minor/Major/Critical)
- Artifact completeness tracking by category
- Determinism rate computation with configurable thresholds
- Release-gated enforcement (determinism + completeness)
- JSONL audit log export
