# bd-1a1l verification summary

## Scope completed
- Fixed manifest compile-breaker by making `SignedExtensionManifest::to_engine_manifest` resilient to extension-host field drift via serde projection and explicit projection error variant.
- Fixed mixed-backend perf assertion overcount by switching backend event filters to exact `backend=<id>` matching.

## Files touched
- `crates/franken-node/src/supply_chain/manifest.rs`
- `tests/perf/vef_proof_service_support_perf.rs`

## Validation evidence (all via `rch`)
1. `rch exec -- cargo check --all-targets`
   - Result: PASS (`exit=0`)
   - Evidence:
     - `artifacts/section_10_18/bd-1a1l/rch_cargo_check_all_targets.log`
     - `artifacts/section_10_18/bd-1a1l/rch_cargo_check_all_targets.exit`
2. `rch exec -- cargo test -p frankenengine-node --test vef_proof_service_support -- --nocapture`
   - Result: PASS (`exit=0`, `99 passed; 0 failed`)
   - Evidence:
     - `artifacts/section_10_18/bd-1a1l/rch_cargo_test_vef_proof_service_support.log`
     - `artifacts/section_10_18/bd-1a1l/rch_cargo_test_vef_proof_service_support.exit`

## Notes
- `rch` artifact retrieval is noisy in this environment (occasional "No artifacts retrieved" warning), but remote command completion lines and explicit `.exit` files confirm pass status.
