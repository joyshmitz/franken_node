# bd-3hm Contract: Migration Singularity Artifact Contract and Verifier Format

**Bead:** bd-3hm
**Section:** 10.12 (Ecosystem Fabric + Network Effects)
**Status:** Active
**Owner:** CrimsonCrane
**Schema:** gate-v1.0

## Overview

Define the artifact contract for migration singularity: a structured, versioned
format for migration outputs including rollback receipts, confidence intervals,
precondition proofs, and verifier-friendly validation metadata. This bridges the
migration system (10.3) and the verifier economy (10.17).

## Data Model

### MigrationArtifact

Top-level artifact struct containing all migration output data.

| Field                 | Type                | Description                                  |
|-----------------------|---------------------|----------------------------------------------|
| `schema_version`      | `String`            | Schema version (e.g. "ma-v1.0")             |
| `plan_id`             | `String`            | Unique plan identifier                       |
| `plan_version`        | `u64`               | Plan version number                          |
| `preconditions`       | `Vec<String>`       | Precondition assertions                      |
| `steps`               | `Vec<MigrationStep>`| Ordered migration steps                      |
| `rollback_receipt`    | `RollbackReceipt`   | Rollback receipt                             |
| `confidence_interval` | `ConfidenceInterval` | Confidence metrics                          |
| `verifier_metadata`   | `VerifierMetadata`  | Verifier-friendly metadata                   |
| `signature`           | `String`            | Cryptographic signature                      |
| `content_hash`        | `String`            | SHA-256 content hash                         |
| `created_at`          | `String`            | RFC 3339 timestamp                           |

### MigrationStep

| Field                  | Type     | Description                          |
|------------------------|----------|--------------------------------------|
| `action_type`          | `String` | Action type (schema_upgrade, etc.)   |
| `target_resource`      | `String` | Resource being modified              |
| `pre_state_hash`       | `String` | Pre-migration state hash             |
| `post_state_hash`      | `String` | Expected post-migration state hash   |
| `rollback_action`      | `String` | Rollback action description          |
| `estimated_duration_ms`| `u64`    | Estimated duration in milliseconds   |

### RollbackReceipt

| Field                    | Type     | Description                         |
|--------------------------|----------|-------------------------------------|
| `original_state_ref`     | `String` | Reference to original state         |
| `rollback_procedure_hash`| `String` | Hash of rollback procedure          |
| `max_rollback_time_ms`   | `u64`    | Max rollback time in ms             |
| `signer_identity`        | `String` | Signer identity                     |
| `signature`              | `String` | Signature over receipt              |

### ConfidenceInterval

| Field                  | Type   | Description                           |
|------------------------|--------|---------------------------------------|
| `probability`          | `f64`  | Overall success probability [0,1]     |
| `dry_run_success_rate` | `f64`  | Dry-run success rate [0,1]            |
| `historical_similarity`| `f64`  | Historical similarity score [0,1]     |
| `precondition_coverage`| `f64`  | Fraction of preconditions verified    |
| `rollback_validation`  | `bool` | Whether rollback was validated        |

### VerifierMetadata

| Field                    | Type                       | Description                     |
|--------------------------|----------------------------|---------------------------------|
| `replay_capsule_refs`    | `Vec<String>`              | Replay capsule references       |
| `expected_state_hashes`  | `BTreeMap<String, String>` | State hashes at checkpoints     |
| `assertion_schemas`      | `Vec<String>`              | JSON Schema URIs                |
| `verification_procedures`| `Vec<String>`              | Verification procedure docs     |

### ArtifactVersion

Enum supporting current and previous major versions.

| Variant | Label    | Description          |
|---------|----------|----------------------|
| `V1_0`  | ma-v1.0  | Current version      |

## Invariants

- **INV-MA-SIGNED** -- Every artifact carries a non-empty signature field.
- **INV-MA-ROLLBACK-PRESENT** -- Every artifact includes a rollback receipt
  with non-empty required fields.
- **INV-MA-CONFIDENCE-CALIBRATED** -- Confidence probability in [0.0, 1.0].
- **INV-MA-VERSIONED** -- Every artifact carries a supported schema version.
- **INV-MA-VERIFIER-COMPLETE** -- Verifier metadata includes at least one
  replay capsule ref and one expected state hash.
- **INV-MA-DETERMINISTIC** -- Same inputs produce byte-identical serialized
  output via BTreeMap and deterministic serialization.

## Event Codes

| Code   | Severity | Description                                |
|--------|----------|--------------------------------------------|
| MA-001 | INFO     | Migration artifact generated               |
| MA-002 | INFO     | Migration artifact signed                  |
| MA-003 | INFO     | Migration artifact validated successfully  |
| MA-004 | WARN     | Schema violation detected                  |
| MA-005 | ERROR    | Signature invalid                          |
| MA-006 | INFO     | Rollback receipt verified                  |
| MA-007 | INFO     | Confidence check passed                    |
| MA-008 | INFO     | Version negotiated                         |

## Error Codes

| Code                       | Description                              |
|----------------------------|------------------------------------------|
| ERR_MA_INVALID_SCHEMA      | Artifact schema validation failed        |
| ERR_MA_SIGNATURE_INVALID   | Artifact signature verification failed   |
| ERR_MA_MISSING_ROLLBACK    | Rollback receipt missing or incomplete   |
| ERR_MA_CONFIDENCE_LOW      | Confidence interval out of valid range   |
| ERR_MA_VERSION_UNSUPPORTED | Schema version not supported             |

## Acceptance Criteria

1. MigrationArtifact struct in `crates/franken-node/src/connector/migration_artifact.rs`
   with all required fields.
2. MigrationStep, RollbackReceipt, ConfidenceInterval, VerifierMetadata structs defined.
3. ArtifactVersion enum with V1_0 variant and parse/label methods.
4. Reference artifact generator function producing valid artifacts.
5. Validation function checking all six invariants.
6. Event codes MA-001 through MA-008 defined in event_codes module.
7. Error codes ERR_MA_* defined in error_codes module.
8. Invariants INV-MA-* defined in invariants module.
9. Schema version "ma-v1.0" constant.
10. JSON Schema at `spec/migration_artifact_schema.json` (Draft 2020-12).
11. Reference vectors at `vectors/migration_artifacts.json`.
12. Serde round-trip for all types.
13. >= 30 unit tests covering all invariants and validation paths.
14. Deterministic content hash via BTreeMap serialization.
15. Module wired into connector/mod.rs.

## Dependencies

- **10.3** (migration system) -- migration plans feed into artifact generation.
- **10.17** (verifier economy) -- verifiers consume artifacts for validation.
- **bd-1l5** (trust object IDs) -- artifacts carry canonical trust object IDs.

## Artifacts

| Artifact                    | Path                                                              |
|-----------------------------|-------------------------------------------------------------------|
| Rust implementation         | `crates/franken-node/src/connector/migration_artifact.rs`         |
| JSON Schema                 | `spec/migration_artifact_schema.json`                             |
| Reference vectors           | `vectors/migration_artifacts.json`                                |
| Spec contract               | `docs/specs/section_10_12/bd-3hm_contract.md`                    |
| Gate script                 | `scripts/check_migration_artifacts.py`                            |
| Test file                   | `tests/test_check_migration_artifacts.py`                         |
| Verification evidence       | `artifacts/section_10_12/bd-3hm/verification_evidence.json`       |
| Verification summary        | `artifacts/section_10_12/bd-3hm/verification_summary.md`          |
