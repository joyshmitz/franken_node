# bd-2vs4: Lease Coordinator — Verification Summary

## Verdict: PASS

## Checks (6/6)

| Check | Description | Status |
|-------|-------------|--------|
| LC-IMPL | Implementation with all required types | PASS |
| LC-ERRORS | All 4 error codes present | PASS |
| LC-VECTORS | Quorum test vectors artifact | PASS |
| LC-CONF-TESTS | Conformance tests cover all 4 invariants | PASS |
| LC-TESTS | Rust unit tests pass (16) | PASS |
| LC-SPEC | Specification with invariants and types | PASS |

## Artifacts

- Spec: `docs/specs/section_10_13/bd-2vs4_contract.md`
- Impl: `crates/franken-node/src/connector/lease_coordinator.rs`
- Conformance: `tests/conformance/lease_coordinator_selection.rs`
- Vectors: `artifacts/section_10_13/bd-2vs4/lease_quorum_vectors.json`
- Evidence: `artifacts/section_10_13/bd-2vs4/verification_evidence.json`

## Test Counts

- Rust unit tests: 16
- Python verification tests: 16
- Conformance tests: 7 (deterministic, quorum_tier ×2, classified ×3, replay)

## Invariants Covered

- **INV-LC-DETERMINISTIC**: Same candidates + lease_id → same coordinator
- **INV-LC-QUORUM-TIER**: Standard=1, Risky=2, Dangerous=3 thresholds
- **INV-LC-VERIFY-CLASSIFIED**: Every failure tagged LC_BELOW_QUORUM / LC_INVALID_SIGNATURE / LC_UNKNOWN_SIGNER
- **INV-LC-REPLAY**: Identical inputs → identical verification result
