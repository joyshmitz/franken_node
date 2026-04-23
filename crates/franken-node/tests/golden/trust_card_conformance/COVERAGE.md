# Trust Card Schema Conformance Coverage

This document tracks which specification requirements are tested vs not tested.

## Coverage Matrix

| Spec Section | MUST Clauses | SHOULD Clauses | Tested | Passing | Divergent | Score |
|-------------|:------------:|:--------------:|:------:|:-------:|:---------:|-------|
| bd-2yh/schema | 3 | 0 | 3 | 3 | 0 | 100.0% |
| bd-2yh/deterministic | 2 | 0 | 2 | 2 | 0 | 100.0% |
| bd-2yh/serialization | 1 | 0 | 1 | 1 | 0 | 100.0% |
| bd-2yh/signature | 2 | 0 | 2 | 0 | 2 | 0.0% (XFAIL) |
| bd-2yh/constraints | 1 | 1 | 2 | 1 | 1 | 50.0% |

**Overall MUST clause coverage: 8/10 (80%)**
**Overall SHOULD clause coverage: 0/1 (0%)**

## Test Cases

### TC-SCHEMA-* (Schema Structure Requirements)
- ✅ **TC-SCHEMA-001** - TrustCard MUST contain all required fields
- ✅ **TC-SCHEMA-002** - schema_version MUST be present and valid  
- ✅ **TC-SCHEMA-003** - trust_card_version MUST be monotonic u64

### TC-SERIAL-* (Serialization Requirements) 
- ✅ **TC-SERIAL-001** - JSON serialization MUST be canonical and deterministic
- ✅ **TC-SERIAL-002** - Field ordering MUST be lexicographic

### TC-ROUND-* (Round-trip Requirements)
- ✅ **TC-ROUND-001** - serialize(deserialize(data)) MUST equal data

### TC-SIG-* (Signature Requirements)
- ❌ **TC-SIG-001** - registry_signature MUST verify with correct key (XFAIL: implementation gap)
- ❌ **TC-SIG-002** - card_hash MUST be derived deterministically (XFAIL: implementation gap)

### TC-EDGE-* (Edge Cases and Constraints)
- ✅ **TC-EDGE-001** - Empty capability_declarations MUST be valid
- ❌ **TC-EDGE-002** - Large audit_history SHOULD be bounded (XFAIL: no bounds enforced)

## What's NOT Tested

1. **Signature verification workflow** - Requires full TrustCardRegistry setup with proper key management
2. **Audit history size limits** - No current enforcement of MAX_AUDIT_HISTORY bounds
3. **Cross-version compatibility** - Serialization compatibility across schema version changes
4. **Performance characteristics** - Large dataset serialization performance
5. **Concurrent access patterns** - Thread safety of trust card operations

## Specification Requirements Reference

Based on bd-2yh contract specification:

### MUST Requirements (Critical)
1. Schema fields must be complete and correctly typed
2. Serialization must be deterministic and canonical
3. Round-trip consistency must be maintained
4. Signatures must verify correctly
5. Required fields cannot be empty

### SHOULD Requirements (Important)
1. Audit history should be bounded to prevent resource exhaustion
2. Error messages should be informative
3. Serialization should be compact

### MAY Requirements (Optional)
1. Additional validation hints may be provided
2. Performance optimizations may be applied
3. Extended metadata may be included

## Target Coverage Goals

- **MUST clauses**: 95%+ (currently 80% due to signature implementation gaps)
- **SHOULD clauses**: 75%+ (currently 0% due to audit bounds)
- **MAY clauses**: Not tracked for conformance

## Next Steps to Improve Coverage

1. Integrate signature testing with proper key management
2. Implement and test audit history bounds enforcement
3. Add cross-version compatibility tests
4. Add performance regression tests for large datasets