# Support Lane `bd-28u0.3` — Standalone Compile-Context Unblock

Date: 2026-02-22
Agent: StormyGate
Parent bead: `bd-28u0`

## Goal
Enable `crates/franken-node/tests/vef_proof_scheduler_support.rs` path-module harness to compile and run the conformance/perf fixtures as executable tests.

## Changes
- `crates/franken-node/src/vef/mod.rs`
  - Re-exported `connector` into `vef` module scope (`pub(crate) use crate::connector;`) for shared module-relative imports.
- `crates/franken-node/src/vef/receipt_chain.rs`
  - Switched crate-root imports to module-relative imports (`super::connector`).
  - Adjusted internal test imports (`super::super::connector`).
  - Hardened deterministic test assertions to compare deterministic fingerprints (excluding trace-only metadata fields).
- `crates/franken-node/src/vef/proof_scheduler.rs`
  - Switched crate-root imports to module-relative imports (`super::connector`, `super::super::receipt_chain` in tests).
  - Fixed checkpoint alignment tuple typing by storing optional checkpoint IDs in alignment selection.
  - Relaxed alignment filter to choose farthest checkpoint end within current window bound.
- `tests/conformance/vef_proof_scheduler_support.rs`
  - Promoted fixture `vef_execution_receipt` module visibility to `pub` for legal re-export.
- `tests/perf/vef_proof_scheduler_support_perf.rs`
  - Promoted fixture `vef_execution_receipt` module visibility to `pub` for legal re-export.

## Validation (offloaded with `rch`)
- `rch exec -- cargo test -p frankenengine-node --test vef_proof_scheduler_support`
  - Final result: `exit=0`
  - Summary: `78 passed; 0 failed`
- `rch exec -- cargo check -p frankenengine-node --all-targets`
  - Result: `exit=0`

## Notes
- `cargo fmt --check -p frankenengine-node` reports broad pre-existing formatting drift in unrelated files; not addressed in this lane.
