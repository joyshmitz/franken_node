# rch Validation Triad (bd-t023)

All commands were run offloaded via `rch` as required.

## Commands + exits

- `rch exec -- cargo check --all-targets` -> exit `101`
- `rch exec -- cargo clippy --all-targets -- -D warnings` -> exit `101`
- `rch exec -- cargo fmt --check` -> exit `1`

## Key blocking findings

### cargo check --all-targets
Primary failures are in new VEF scheduler support harness wiring and module visibility/import paths:

- `crates/franken-node/tests/../../../tests/conformance/vef_proof_scheduler_support.rs`
  - `E0365`: attempted re-export of private `vef_execution_receipt`
- `crates/franken-node/tests/../../../tests/perf/vef_proof_scheduler_support_perf.rs`
  - `E0365`: attempted re-export of private `vef_execution_receipt`
- `crates/franken-node/tests/../../../tests/conformance/../../crates/franken-node/src/vef/receipt_chain.rs`
  - `E0433`: cannot find `crate::connector` in this integration-test crate context
- `crates/franken-node/tests/../../../tests/conformance/../../crates/franken-node/src/vef/proof_scheduler.rs`
  - `E0433`: cannot find `crate::connector` / `crate::vef` in this integration-test crate context
  - `E0308`: `aligned.unwrap_or((max_end, None))` type mismatch around `aligned_checkpoint_id`

These findings match active support bead `bd-28u0.2` scope.

### cargo clippy --all-targets -- -D warnings
Fails with broad pre-existing warnings-as-errors across unrelated modules (unused imports/variables, clippy style and API lints). Not specific to `bd-t023` runtime edits.

### cargo fmt --check
Fails with extensive formatting drift across many files (large rustfmt diff output).

## Context on bd-t023 runtime edits

Runtime edits made in this lane are:

- `crates/franken-node/src/runtime/time_travel.rs`
  - added `#[derive(Debug)]` to `ReplaySession`
- `crates/franken-node/src/runtime/isolation_mesh.rs`
  - ended mutable workload borrow before `push_event` in `elevate_workload`

A targeted post-fix run succeeded:

- `rch exec -- cargo test -p frankenengine-node vef_adversarial_suite -- --nocapture` -> exit `0`

So the current triad failures are outside the direct `bd-t023` runtime fix scope.
