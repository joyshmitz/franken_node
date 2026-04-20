# Trust Card Cross-Version Conformance Discrepancies

This document tracks all known divergences from perfect cross-version compatibility
for trust card schemas and verification logic.

## Overview

Trust card conformance testing validates compatibility between different versions:
- **Backward compatibility**: old trust-cards × new verifier
- **Forward compatibility**: new trust-cards × old verifier  
- **Schema transitions**: version chain validation across schema changes
- **Signature verification**: cross-version signature compatibility

## Known Divergences

### DISC-001: Future Schema Rejection
- **Reference:** Current verifier (schema v1.0.0)
- **Test case:** `future_card_current_verifier`  
- **Behavior:** Current verifier rejects trust cards with schema > 1.0.0
- **Expected result:** Graceful failure with `UnsupportedSchemaVersion` error
- **Impact:** Forward compatibility intentionally limited
- **Resolution:** ACCEPTED — verifiers should fail-closed on unknown schemas
- **Tests affected:** `registry_future_schema_error`
- **Review date:** 2024-01-01

### DISC-002: Legacy Schema Support Window
- **Reference:** Current verifier (schema v1.0.0) 
- **Test case:** `legacy_card_current_verifier`
- **Behavior:** Current verifier accepts cards with schema ≥ 0.9.0
- **Expected result:** Pass with backward compatibility warnings
- **Impact:** Limited backward compatibility window (not indefinite)
- **Resolution:** ACCEPTED — maintain 1-2 version backward compatibility only
- **Tests affected:** `legacy_card_current_verifier`, `mixed_schema_history`
- **Review date:** 2024-01-01

### DISC-003: Schema Version String Format
- **Reference:** Trust card schema uses semantic versioning (e.g., "1.0.0")
- **Test case:** Schema version validation throughout test matrix
- **Behavior:** String comparison for schema version compatibility
- **Expected result:** Exact string match required
- **Impact:** Minor version differences (1.0.0 vs 1.0.1) treated as incompatible
- **Resolution:** INVESTIGATING — may need semantic version comparison
- **Tests affected:** All cross-version tests
- **Review date:** 2024-01-01

## Testing Strategy

### Accepted Divergences (XFAIL)
Tests that fail by design use `TestExpectation::Fail` to document expected failure:

```rust
CrossVersionTest {
    name: "future_card_current_verifier", 
    expected_result: TestExpectation::Fail("unsupported_schema"),
}
```

### Warning Cases (XFAIL)
Non-critical compatibility issues use `TestExpectation::WarningButPass`:

```rust
CrossVersionTest {
    name: "legacy_card_current_verifier",
    expected_result: TestExpectation::WarningButPass, 
}
```

## Conformance Score Calculation

**Target:** ≥95% conformance for MUST-level compatibility requirements

**Current Status:** 
- Backward compatibility (MUST): 100% (1/1 tests pass)  
- Forward compatibility (SHOULD): 0% (intentionally fail-closed)
- Schema transitions (MUST): 100% (1/1 tests pass)
- Mixed histories (SHOULD): 100% (1/1 tests pass)

**Overall:** 75% (3/4 test categories fully conformant)

## Review Schedule

- **Quarterly:** Review all divergences for continued validity
- **Before releases:** Check if version compatibility window needs adjustment
- **After schema changes:** Re-run full conformance matrix

## References

- Trust card schema specification: `src/supply_chain/trust_card.rs`
- Registry snapshot schema: `TRUST_CARD_REGISTRY_SNAPSHOT_SCHEMA` 
- Cross-version test matrix: `tests/trust_card_cross_version_conformance.rs`