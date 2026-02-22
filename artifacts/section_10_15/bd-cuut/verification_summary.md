# bd-cuut: Control-Plane Lane Mapping Policy -- Verification Summary

**Section:** 10.15 | **Bead:** bd-cuut | **Date:** 2026-02-22

## Gate Result: PASS

| Metric | Value |
|--------|-------|
| Rust in-module tests | 29 |
| Python gate checks | 60/60 |
| Python unit tests | 44/44 |
| Event codes | 8 (CLM_TASK_ASSIGNED..CLM_STARVATION_CLEARED) |
| Error codes | 6 (ERR_CLM_UNKNOWN_TASK..ERR_CLM_INCOMPLETE_MAP) |
| Invariants | 6 verified (INV-CLM-*) |
| Schema version | clm-v1.0 |
| Task classes | 14 across 3 lanes |

## Implementation

- `crates/franken-node/src/control_plane/control_lane_mapping.rs` -- Lane mapping policy
- `crates/franken-node/src/control_plane/mod.rs` -- Module registration
- `docs/specs/section_10_15/bd-cuut_contract.md` -- Spec contract
- `scripts/check_control_lane_mapping.py` -- Verification gate
- `tests/test_check_control_lane_mapping.py` -- Python test suite

## Key Capabilities

- Three-lane model: Cancel (priority 0), Timed (priority 1), Ready (priority 2)
- 14 well-known task classes with lane assignments
- Budget enforcement: Cancel >= 20%, Timed >= 30%, Ready = 50%
- Starvation detection with per-lane configurable thresholds
- Priority-based scheduling: Cancel preempts Ready when both pending
- JSONL audit log with schema_version field
- CSV starvation metrics export (7 columns)
- Validate() enforces budget sum <= 100% and per-lane minimums
