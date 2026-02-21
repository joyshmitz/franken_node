# bd-f2y Verification Summary

## Bead

- **ID**: bd-f2y
- **Section**: 10.8
- **Title**: Incident bundle retention and export policy

## Verdict: PASS

All 34 verification checks pass.  89 Python unit tests pass.  40 Rust unit tests in the implementation module.

## Deliverables

| # | Deliverable | Path | Status |
|---|-------------|------|--------|
| 1 | Spec contract | `docs/specs/section_10_8/bd-f2y_contract.md` | Created |
| 2 | Policy document | `docs/policy/incident_bundle_retention.md` | Created |
| 3 | Rust implementation | `crates/franken-node/src/connector/incident_bundle_retention.rs` | Created |
| 4 | Module wiring | `crates/franken-node/src/connector/mod.rs` | Updated |
| 5 | Verification script | `scripts/check_incident_bundles.py` | 34 checks, all PASS |
| 6 | Unit tests | `tests/test_check_incident_bundles.py` | 89 tests, all PASS |
| 7 | Evidence JSON | `artifacts/section_10_8/bd-f2y/verification_evidence.json` | Generated |
| 8 | Summary (this file) | `artifacts/section_10_8/bd-f2y/verification_summary.md` | Generated |

## Check Categories

### Spec Contract (C01, C09-C16)
- File existence, event codes IBR-001 through IBR-004, invariants INV-IBR-*
- Export formats (JSON, CSV, SARIF), retention tiers (hot/cold/archive)
- Retention periods (90/365/2555 days), bundle format (11 required fields)
- Dependencies, acceptance criteria

### Policy Document (C02, C17-C24)
- Retention schedule, export procedures, compliance requirements
- Governance, event codes, invariants, automated cleanup, audit trail

### Implementation (C03, C08, C25-C34)
- File existence, module wiring in connector/mod.rs
- 9 required types: Severity, RetentionTier, ExportFormat, BundleMetadata,
  IncidentBundle, RetentionConfig, RetentionDecision, IncidentBundleStore,
  IncidentBundleError
- 5 required functions: compute_integrity_hash, validate_bundle_complete,
  export_csv_row, csv_header, export_sarif
- Event codes, invariant doc comments, retention defaults
- Test module, severity enum, export format variants
- Archive protection, integrity verification

### Upstream Dependencies (C04-C07)
- retention_policy.rs (10.13, bd-1p2b): RetentionClass/RetentionStore
- replay_bundle.rs (10.5, bd-vll): Deterministic replay bundles
- config.rs: Configuration system for retention period tuning
- health_gate.rs: Capacity alert integration

## Test Coverage

The 89 Python unit tests cover:
- **run_all structure** (8 tests): return type, required keys, bead_id, section, verdict, totals
- **self_test** (2 tests): return type, passes
- **individual checks** (34 tests): one per check function, all pass
- **missing file detection** (4 tests): spec, policy, impl, retention_policy
- **validate_retention_period** (8 tests): all tiers valid/below-minimum, unknown tier
- **validate_bundle_fields** (4 tests): complete bundle, missing fields, none values
- **validate_severity** (6 tests): all 4 levels, invalid, empty
- **validate_retention_tier** (5 tests): all 3 tiers, invalid, empty
- **validate_export_format** (6 tests): all 3 formats, uppercase, invalid, empty
- **constants** (8 tests): counts for all constant arrays and check lists
- **JSON output** (2 tests): serializable, subprocess --json flag
- **safe_rel** (2 tests): root path, non-root path

The 40 Rust unit tests cover:
- Severity labels and from_str (5 tests)
- RetentionTier labels and from_str (4 tests)
- ExportFormat labels, extensions, and from_str (4 tests)
- RetentionConfig defaults (1 test)
- Integrity hash determinism and variation (2 tests)
- Bundle completeness validation (3 tests)
- Store operations: store, reject bad integrity, reject full (3 tests)
- Export: JSON, CSV, SARIF, not found (4 tests)
- Tier rotation: hot-to-cold, cold-to-archive (2 tests)
- Archive protection and force delete (3 tests)
- Cleanup with rotation (1 test)
- Decision audit trail (1 test)
- Utilization, warn level, critical level (3 tests)
- Bundles-by-tier query (1 test)
- CSV header and row export (2 tests)
- SARIF export fields (1 test)
- Error codes completeness and display (2 tests)
- Event code values (1 test)
- Invalid config rejection (1 test)

## Implementation Highlights

### Tiered Retention Model
- **Hot** (90 days): Active incident bundles for ongoing investigation
- **Cold** (365 days): Compressed storage for trend analysis and audit
- **Archive** (2555 days / 7 years): Immutable compliance retention, never auto-deleted

### Export Formats
- **JSON**: Full-fidelity with integrity hash for round-trip verification
- **CSV**: Flattened tabular format for spreadsheet analysis
- **SARIF v2.1.0**: Security incident integration with SAST/DAST tooling

### Invariant Enforcement
- INV-IBR-COMPLETE: All bundles validated at creation time
- INV-IBR-RETENTION: Automated tier transitions; archive protection
- INV-IBR-EXPORT: Integrity hash verified before every export
- INV-IBR-INTEGRITY: Hash computed deterministically, verified on store and read

### Audit Trail
- Every operation (create, transition, export, delete, cleanup) logged as RetentionDecision
- Each decision includes event code, timestamp, bundle ID, and reason
