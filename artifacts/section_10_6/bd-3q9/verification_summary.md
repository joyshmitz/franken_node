# bd-3q9: Release Rollback Bundles with Deterministic Restore Checks

**Section:** 10.6 | **Verdict:** PASS | **Date:** 2026-02-20

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Python verification checks | 149 | 149 |
| Rust unit tests | 48 | 48 |
| Python unit tests | 65 | 65 |

## Implementation

**File:** `crates/franken-node/src/connector/rollback_bundle.rs` (~1500 lines)

### Core Types (14)
- `RollbackBundle`, `BundleStore`, `BundleComponent`, `RestoreManifest`
- `ManifestComponent`, `CompatibilityProof`, `StateSnapshot`
- `HealthCheckResult`, `HealthCheckKind`, `RollbackResult`, `RollbackAction`
- `RollbackAuditEntry`, `RollbackBundleError`, `RollbackMode`

### Key Methods (22)
- `BundleStore::create_bundle()` - generates rollback bundle with manifest
- `BundleStore::apply_rollback()` - applies bundle with health checks
- `RollbackBundle::verify_integrity()` - SHA-256 checksum verification
- `RollbackBundle::check_compatibility()` - version bounds validation
- `StateSnapshot::diff()` - deterministic state comparison
- `RollbackResult::to_json()` - structured JSON output

### Event Codes
| Code | Description |
|------|-------------|
| RRB-001 | Bundle created |
| RRB-002 | Rollback initiated |
| RRB-003 | Rollback completed |
| RRB-004 | Rollback failed |

### Invariants
| ID | Statement |
|----|-----------|
| INV-RRB-DETERM | Byte-identical state after rollback |
| INV-RRB-IDEMPOT | Same result on repeated application |
| INV-RRB-HEALTH | Health checks must pass for success |
| INV-RRB-MANIFEST | All components listed with correct checksums |

### Error Codes
| Code | Meaning |
|------|---------|
| ERR-RRB-MANIFEST-INVALID | Malformed or invalid manifest |
| ERR-RRB-CHECKSUM-MISMATCH | Component checksum mismatch |
| ERR-RRB-HEALTH-FAILED | Post-rollback health check failure |
| ERR-RRB-VERSION-MISMATCH | Bundle targets wrong version |

### Health Check Sequence
1. Binary version verification
2. Configuration schema validation
3. State integrity check
4. Core workflow smoke tests

## Formal Properties

- **Determinism**: `StateSnapshot::snapshot_hash()` is deterministic; `diff()` detects all field-level mismatches
- **Idempotency**: Tested via `test_apply_rollback_idempotent` — second apply produces identical state
- **Dry-run isolation**: `test_dry_run_no_state_change` verifies no state mutation in preview mode
