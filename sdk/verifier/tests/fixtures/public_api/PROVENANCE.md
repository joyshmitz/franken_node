# Public API Fixtures Provenance

## Generation Method

These fixtures were created manually for the verifier SDK public API conformance tests.
They use deterministic values to ensure stable golden file comparisons.

## Deterministic Values Used

- **Timestamps**: Fixed to `2026-04-21T12:00:00Z` and sequential seconds for ordering
- **Hashes**: Deterministic hex patterns starting with `sha256:a1b2c3d4e5f6789...`
- **Signatures**: Fixed Ed25519 signature hex `deadbeefcafebabe0123456789abcdef...`
- **IDs**: Prefixed with descriptive names like `test-verifier-deterministic`, `bundle-deterministic-test-001`
- **Counters**: Start from 0 or 1 with predictable increments

## Fixture Files

### facade_result.json
- **Source**: Manual creation based on `VerificationResult` structure
- **Purpose**: Golden reference for main API result format
- **Key Fields**: All required fields with deterministic test values

### session_step.json  
- **Source**: Manual creation based on `SessionStep` structure
- **Purpose**: Golden reference for session step format
- **Key Fields**: Minimal required fields only

### transparency_entry.json
- **Source**: Manual creation based on `TransparencyLogEntry` structure
- **Purpose**: Golden reference for transparency log format
- **Key Fields**: Result hash, timestamp, verifier ID, merkle proof array

### bundle_canonical.json
- **Source**: Manual creation based on `ReplayBundle` structure from `bundle.rs`
- **Purpose**: Golden reference for canonical bundle format
- **Key Fields**: Complete bundle with header, timeline, artifacts, signature

### error_matrix.json
- **Source**: Manual creation based on error enum variants from SDK source
- **Purpose**: Expected error display format testing
- **Structure**: Organized by error category (bundle_errors, sdk_errors)

### api_manifest.json
- **Source**: Manual extraction of public API surface from SDK source code
- **Purpose**: API contract metadata and breaking change policies
- **Structure**: Constants, enums, structures, functions with requirement levels

## Regeneration Instructions

To regenerate these fixtures if the API changes:

1. **Constants**: Extract from `src/lib.rs` and `src/bundle.rs` 
2. **Enums**: Check serde representation in source code
3. **Structures**: Update field lists and types from struct definitions
4. **Errors**: Verify error display format implementations
5. **Bundle format**: Ensure structure matches `bundle::ReplayBundle`

Always use the same deterministic values to maintain test stability.

## Last Updated

2026-04-21 - Initial creation for bd-1qqbu public API conformance harness

## SDK Version Compatibility

These fixtures are compatible with SDK version `vsdk-v1.0` and replay bundle schema `vsdk-replay-bundle-v1.0`.