# bd-17z7.5 verification summary

## Scope
Lane scheduler queue-depth telemetry integrity in `crates/franken-node/src/runtime/lane_scheduler.rs`.

## Defect fixed
`complete_task` was decrementing `queued_count` on completion even when no queued task was admitted. This could hide backlog pressure and skew starvation telemetry.

## Code changes
- `assign_task`:
  - on successful admission, drains one pending queue slot (`queued_count -= 1` when `queued_count > 0`).
- `complete_task`:
  - removed implicit queue drain; completion now only updates active/completed/last_completion metrics.
- Added regression tests:
  - `completion_does_not_drain_queue_depth_without_admission`
  - `successful_assignment_drains_one_pending_queue_slot`

## Verification
All heavy validation was offloaded through `rch`.

1. `rch exec -- env CARGO_TARGET_DIR=target/rch_bd17z7_5_check cargo check -p frankenengine-node --all-targets` -> **PASS**
2. `rch exec -- env CARGO_TARGET_DIR=target/rch_bd17z7_5_clippy cargo clippy -p frankenengine-node --all-targets -- -D warnings` -> **PASS**
3. `rch exec -- env CARGO_TARGET_DIR=target/rch_bd17z7_5_lane_scheduler_tests cargo test -p frankenengine-node --bin frankenengine-node runtime::lane_scheduler::tests -- --nocapture` -> **PASS** (`33 passed; 0 failed`)
4. `rustfmt +nightly --edition 2024 --check crates/franken-node/src/runtime/lane_scheduler.rs` -> **PASS**
