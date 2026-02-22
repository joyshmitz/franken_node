# bd-17z7.4 verification summary

## Scope
Runtime `GlobalBulkhead` permit/operation integrity hardening and router mapping compatibility.

## Defect fixed
`GlobalBulkhead::release` previously accepted any `operation_id` for a valid `permit_id`, which allowed release attribution spoofing and incorrect identity association during permit release.

## Code changes
- `crates/franken-node/src/runtime/bulkhead.rs`
  - Replaced `active_permits: BTreeSet<String>` with `BTreeMap<String, String>` mapping `permit_id -> operation_id`.
  - Added new stable error code and error variant:
    - `BULKHEAD_PERMIT_OPERATION_MISMATCH`
    - `BulkheadError::PermitOperationMismatch { permit_id, expected_operation_id, provided_operation_id }`
  - Hardened `release`:
    - unknown permit: fail closed (`UnknownPermit`)
    - mismatched operation id: fail closed (`PermitOperationMismatch`) without releasing permit
    - only exact permit+operation match decrements in-flight and emits release event
  - Added regression test:
    - `release_with_mismatched_operation_is_rejected_without_releasing_permit`
- `crates/franken-node/src/runtime/lane_router.rs`
  - Updated `map_bulkhead_err` exhaustiveness to handle `PermitOperationMismatch` deterministically as `LaneRouterError::InvalidConfig` with detail payload.

## Verification
All CPU-intensive checks/tests were offloaded through `rch`.

1. `rch exec -- env CARGO_TARGET_DIR=target/rch_bd17z7_4_check cargo check -p frankenengine-node --all-targets` -> **PASS**
2. `rch exec -- env CARGO_TARGET_DIR=target/rch_bd17z7_4_clippy cargo clippy -p frankenengine-node --all-targets -- -D warnings` -> **PASS**
3. `rch exec -- env CARGO_TARGET_DIR=target/rch_bd17z7_4_bulkhead_tests cargo test -p frankenengine-node --bin frankenengine-node runtime::bulkhead::tests -- --nocapture` -> **PASS** (`11 passed; 0 failed`)
4. `rch exec -- env CARGO_TARGET_DIR=target/rch_bd17z7_4_lane_router_tests cargo test -p frankenengine-node --bin frankenengine-node runtime::lane_router::tests -- --nocapture` -> **PASS** (`14 passed; 0 failed`)
5. `rustfmt +nightly --edition 2024 --check crates/franken-node/src/runtime/bulkhead.rs crates/franken-node/src/runtime/lane_router.rs` -> **PASS**
