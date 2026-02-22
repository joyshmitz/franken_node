# bd-17z7.1 verification summary

## Scope
- Activated previously un-exported runtime modules in `crates/franken-node/src/runtime/mod.rs`:
  - `bulkhead`
  - `cancellable_task`
  - `lane_router`
- Fixed `cancellable_task` nested-propagation correctness and idempotency behavior:
  - `register_child` now rejects unknown child task IDs
  - duplicate child link registration is idempotent
- Resolved borrow-check defects surfaced once dead modules were compiled.

## Code changes
- `crates/franken-node/src/runtime/mod.rs`
  - Exported `bulkhead`, `cancellable_task`, and `lane_router`.
- `crates/franken-node/src/runtime/cancellable_task.rs`
  - `register_child`: added unknown-child guard and duplicate-link idempotency.
  - `cancel_task`: refactored borrow scopes to avoid immutable+mutable aliasing.
  - Added tests:
    - `register_child_rejects_unknown_child`
    - `register_child_duplicate_link_is_idempotent`
- `crates/franken-node/src/runtime/lane_router.rs`
  - Refactored borrow scopes in `assign_operation` and `promote_queued` to avoid overlapping mutable borrows of `self`.

## Remote verification (RCH)
All compile/test validation commands were executed through `rch exec -- ...`.

1. `cargo check -p frankenengine-node --all-targets` (RCH): **PASS**
2. `cargo test -p frankenengine-node --bin frankenengine-node register_child_rejects_unknown_child -- --nocapture` (RCH): **PASS**
   - observed: `running 1 test` and test name `runtime::cancellable_task::tests::register_child_rejects_unknown_child ... ok`
3. `cargo test -p frankenengine-node --bin frankenengine-node register_child_duplicate_link_is_idempotent -- --nocapture` (RCH): **PASS**
   - observed: `running 1 test` and test name `runtime::cancellable_task::tests::register_child_duplicate_link_is_idempotent ... ok`
4. `cargo clippy -p frankenengine-node --all-targets -- -D warnings` (RCH): **PASS**

## Formatting status
- `rustfmt +nightly --edition 2024 --check` on touched files:
  - `crates/franken-node/src/runtime/mod.rs`
  - `crates/franken-node/src/runtime/cancellable_task.rs`
  - `crates/franken-node/src/runtime/lane_router.rs`
  - Result: **PASS**

Note: `cargo fmt --all --check` is not intercepted by current `rch` command classification (non-compilation command), and in this environment it reports many unrelated pre-existing formatting diffs in sibling repositories (not part of this bead lane).
