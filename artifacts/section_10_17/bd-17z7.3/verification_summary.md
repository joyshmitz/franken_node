# bd-17z7.3 verification summary

## Scope
Deep runtime audit and hardening of `LaneRouter` behavior in `crates/franken-node/src/runtime/lane_router.rs`.

## Defects fixed
- Enforced duplicate operation-id rejection across both active and queued operations.
  - Added `queued_operation_ids` index to prevent queued duplicates.
  - Kept index synchronized on enqueue, expiry eviction, queue shedding, and queue promotion.
- Hardened lane-hint routing against scope mismatch.
  - A valid lane hint is now honored only if `CapabilityContext` contains matching lane scope.
  - Mismatches fail closed to background and emit `LANE_DEFAULTED_BACKGROUND` with `lane_hint_scope_mismatch=...` detail.
- Filled missing saturation telemetry for `ShedOldest` on non-background lanes.
  - `LANE_SATURATED` event is now emitted before returning `LANE_SATURATED` error.

## Tests added
- `lane_hint_scope_mismatch_defaults_to_background`
- `duplicate_operation_id_rejected_while_queued`
- `expired_queued_operation_can_be_reused_after_eviction`
- `non_background_shed_oldest_emits_lane_saturated_event`

## Verification
All CPU-intensive validation was offloaded through `rch`.

1. `rch exec -- env CARGO_TARGET_DIR=target/rch_bd17z7_3_fix_check cargo check -p frankenengine-node --all-targets` -> **PASS**
2. `rch exec -- env CARGO_TARGET_DIR=target/rch_bd17z7_3_fix_clippy cargo clippy -p frankenengine-node --all-targets -- -D warnings` -> **PASS**
3. `rch exec -- env CARGO_TARGET_DIR=target/rch_bd17z7_3_fix_tests cargo test -p frankenengine-node --bin frankenengine-node runtime::lane_router::tests -- --nocapture` -> **PASS**
   - observed: `running 14 tests`, `14 passed; 0 failed`
4. `rustfmt +nightly --edition 2024 --check crates/franken-node/src/runtime/lane_router.rs` -> **PASS**
