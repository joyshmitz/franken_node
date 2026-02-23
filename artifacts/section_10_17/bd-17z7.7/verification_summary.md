# bd-17z7.7 Verification Summary

## Scope
- Bead: `bd-17z7.7`
- Parent: `bd-17z7`
- File: `crates/franken-node/src/runtime/hardware_planner.rs`

## Defect
`PlacementPolicy.required_metadata_keys` was defined but never enforced in placement evaluation. This allowed workloads to be scheduled onto profiles missing policy-required metadata.

## Fix
- Enforced policy metadata constraints in phase-1 candidate filtering during `request_placement`.
- Rejection evidence now records missing required metadata keys in `PolicyEvidence.rejections` and `reasoning_chain`.
- Added regression tests:
  - `policy_required_metadata_keys_are_enforced`
  - `placement_rejected_when_policy_metadata_constraints_not_met`

## Validation
All CPU-intensive validation was offloaded through `rch`.

1. `rch exec -- env CARGO_TARGET_DIR=target/rch_bd17z7_7_check cargo check -p frankenengine-node --all-targets`
   - Result: PASS (exit 0)
2. `rch exec -- env CARGO_TARGET_DIR=target/rch_bd17z7_7_clippy cargo clippy -p frankenengine-node --all-targets -- -D warnings`
   - Result: PASS (exit 0)
3. `rch exec -- env CARGO_TARGET_DIR=target/rch_bd17z7_7_hwplanner_tests cargo test -p frankenengine-node --bin frankenengine-node runtime::hardware_planner::tests -- --nocapture`
   - Result: PASS (37 passed, 0 failed)
4. `rustfmt +nightly --edition 2024 --check crates/franken-node/src/runtime/hardware_planner.rs`
   - Result: PASS

## Outcome
Metadata-based policy constraints are now enforced and fail closed when unmet, with deterministic audit evidence.
