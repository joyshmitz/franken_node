# bd-17z7.9 Verification Summary

## Scope
- Bead: `bd-17z7.9`
- Parent: `bd-17z7`
- File: `crates/franken-node/src/runtime/hardware_planner.rs`

## Defect
`HardwarePlanner::dispatch` allowed dispatch for any known profile via an approved interface even when no successful placement existed for the workload/target pair. This bypassed placement policy enforcement and violated dispatch authorization expectations.

## Fix
- Added `ERR_HWP_DISPATCH_NOT_PLACED` and `HardwarePlannerError::DispatchNotPlaced`.
- Hardened `dispatch` to require at least one prior successful placement decision (`Placed` or `PlacedViaFallback`) for the exact `(workload_id, target_profile_id)` pair.
- Updated dispatch tests to require a real placement on the happy path.
- Added regression test:
  - `dispatch_without_successful_placement_rejected`

## Validation
All CPU-intensive validation was run through `rch`.

1. `rch exec -- env CARGO_TARGET_DIR=target/rch_bd17z7_9_check cargo check -p frankenengine-node --all-targets`
   - Initial run encountered a transient unrelated compile error in another file due concurrent workspace churn.
2. `rch exec -- env CARGO_TARGET_DIR=target/rch_bd17z7_9_check2 cargo check -p frankenengine-node --all-targets`
   - Result: PASS (exit 0)
3. `rch exec -- env CARGO_TARGET_DIR=target/rch_bd17z7_9_clippy cargo clippy -p frankenengine-node --all-targets -- -D warnings`
   - Result: PASS (exit 0)
4. `rch exec -- env CARGO_TARGET_DIR=target/rch_bd17z7_9_hwplanner_tests cargo test -p frankenengine-node --bin frankenengine-node runtime::hardware_planner::tests -- --nocapture`
   - Result: PASS (38 passed, 0 failed)
5. `rustfmt +nightly --edition 2024 --check crates/franken-node/src/runtime/hardware_planner.rs`
   - Result: PASS

## Outcome
Dispatch now fails closed unless policy-approved placement has already been established for the target.
