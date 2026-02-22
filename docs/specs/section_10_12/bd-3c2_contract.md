# bd-3c2 Contract: Verifier-Economy SDK with Independent Validation Workflows

**Bead:** bd-3c2
**Section:** 10.12 (Ecosystem Fabric + Network Effects)
**Status:** Active
**Owner:** CrimsonCrane
**Schema:** gate-v1.0

## Overview

Implement a verifier SDK that enables independent third parties to verify
claims, migration artifacts, trust state, and replay capsules. The SDK is
the bridge to the verifier economy, making independent verification easy
and reliable.

## Data Model

### Claim

A verifiable claim about a subject.

| Field           | Type          | Description                        |
|-----------------|---------------|------------------------------------|
| `claim_id`      | `String`      | Unique claim identifier            |
| `claim_type`    | `String`      | Type of claim                      |
| `subject`       | `String`      | Subject of the claim               |
| `assertion`     | `String`      | The assertion being made           |
| `evidence_refs` | `Vec<String>` | References to evidence items       |
| `timestamp`     | `String`      | RFC 3339 timestamp                 |

### Evidence

A single piece of evidence supporting a claim.

| Field                    | Type                       | Description                     |
|--------------------------|----------------------------|---------------------------------|
| `evidence_id`            | `String`                   | Unique evidence identifier      |
| `claim_ref`              | `String`                   | Reference to the claim          |
| `artifacts`              | `BTreeMap<String, String>` | Signatures, hashes, timestamps  |
| `verification_procedure` | `String`                   | Verification procedure desc     |

### EvidenceBundle

Self-contained bundle of claim and evidence.

| Field             | Type             | Description                          |
|-------------------|------------------|--------------------------------------|
| `claim`           | `Claim`          | The claim                            |
| `evidence_items`  | `Vec<Evidence>`  | Evidence items supporting the claim  |
| `self_contained`  | `bool`           | Whether bundle is self-contained     |

### VerificationResult

Outcome of a verification operation.

| Field                  | Type                     | Description                         |
|------------------------|--------------------------|-------------------------------------|
| `verdict`              | `Verdict`                | Pass / Fail / Inconclusive          |
| `confidence_score`     | `f64`                    | Confidence score [0,1]              |
| `checked_assertions`   | `Vec<AssertionResult>`   | Individual assertion results        |
| `execution_timestamp`  | `String`                 | RFC 3339 timestamp                  |
| `verifier_identity`    | `String`                 | Verifier identity                   |
| `artifact_binding_hash`| `String`                 | Hash binding result to evidence     |
| `verifier_signature`   | `String`                 | Verifier signature over result      |

### ReplayResult

Outcome of replaying a capsule.

| Field                | Type     | Description                     |
|----------------------|----------|---------------------------------|
| `verdict`            | `Verdict`| Pass / Fail / Inconclusive      |
| `expected_output_hash`| `String`| Expected output hash            |
| `actual_output_hash` | `String` | Actual output hash from replay  |
| `replay_duration_ms` | `u64`    | Replay duration in milliseconds |

### ValidationWorkflow

Workflow context enum.

| Variant               | Description               |
|-----------------------|---------------------------|
| `ReleaseValidation`   | Release validation context |
| `IncidentValidation`  | Incident validation context|
| `ComplianceAudit`     | Compliance audit context   |

### TransparencyLogEntry

Append-only transparency log entry.

| Field          | Type          | Description                     |
|----------------|---------------|---------------------------------|
| `result_hash`  | `String`      | Hash of the verification result |
| `timestamp`    | `String`      | RFC 3339 timestamp              |
| `verifier_id`  | `String`      | Verifier identity               |
| `merkle_proof` | `Vec<String>` | Merkle proof chain              |

## Core Operations

- `verify_claim(claim, evidence, verifier_identity) -> VerificationResult`
- `verify_migration_artifact(artifact, verifier_identity) -> VerificationResult`
- `verify_trust_state(state, anchor, verifier_identity) -> VerificationResult`
- `replay_capsule(capsule_data, expected_output_hash) -> ReplayResult`
- `validate_bundle(bundle) -> Result<(), VerifierSdkError>`
- `append_transparency_log(log, result) -> TransparencyLogEntry`
- `execute_workflow(workflow, bundle, verifier_identity) -> VerificationResult`

## Invariants

- **INV-VER-DETERMINISTIC** -- Same inputs always produce the same verification result.
- **INV-VER-OFFLINE-CAPABLE** -- All core verification operations work without network access.
- **INV-VER-EVIDENCE-BOUND** -- A verification result is cryptographically bound to its evidence via artifact_binding_hash.
- **INV-VER-RESULT-SIGNED** -- Every verification result carries a non-empty verifier_signature.
- **INV-VER-TRANSPARENCY-APPEND** -- Transparency log entries are append-only and hash-chained.

## Event Codes

| Code    | Severity | Description                              |
|---------|----------|------------------------------------------|
| VER-001 | INFO     | Claim verified successfully              |
| VER-002 | WARN     | Claim verification failed                |
| VER-003 | INFO     | Migration artifact verified              |
| VER-004 | INFO     | Trust state verified                     |
| VER-005 | INFO     | Replay completed                         |
| VER-006 | INFO     | Verification result signed               |
| VER-007 | INFO     | Transparency log entry appended          |
| VER-008 | INFO     | Evidence bundle validated                |
| VER-009 | INFO     | Offline verification check performed     |
| VER-010 | INFO     | Validation workflow completed            |

## Error Codes

| Code                      | Description                                 |
|---------------------------|---------------------------------------------|
| ERR_VER_INVALID_CLAIM     | Claim has missing or invalid fields         |
| ERR_VER_EVIDENCE_MISSING  | No evidence provided for verification       |
| ERR_VER_SIGNATURE_INVALID | Signature verification failed               |
| ERR_VER_HASH_MISMATCH     | Hash does not match expected value          |
| ERR_VER_REPLAY_DIVERGED   | Replay output differs from expected output  |
| ERR_VER_ANCHOR_UNKNOWN    | Trust anchor is unknown or empty            |
| ERR_VER_BUNDLE_INCOMPLETE | Evidence bundle is missing required items   |

## Acceptance Criteria

1. Verifier SDK module in `crates/franken-node/src/connector/verifier_sdk.rs` with all required types and operations.
2. Claim, Evidence, EvidenceBundle, VerificationResult, ReplayResult, ValidationWorkflow, TransparencyLogEntry types defined.
3. Core operations: verify_claim, verify_migration_artifact, verify_trust_state, replay_capsule.
4. Event codes VER-001 through VER-010 defined in event_codes module.
5. Error codes ERR_VER_* defined in error_codes module.
6. Invariants INV-VER-* defined in invariants module.
7. Schema version "ver-v1.0" constant.
8. JSON Schema at `spec/evidence_bundle_schema.json` (Draft 2020-12).
9. Serde round-trip for all types.
10. >= 25 unit tests covering all invariants and operations.
11. BTreeMap usage for deterministic serialization.
12. Module wired into connector/mod.rs.
13. Offline-capable: no network calls in core operations.
14. Transparency log append-only with hash chaining.
15. Validation workflows for release, incident, and compliance contexts.

## Dependencies

- **bd-3hm** (migration artifact contract) -- verifier SDK validates migration artifacts.
- **bd-5si** (trust fabric) -- trust state verification context.
- **10.17** (verifier economy) -- SDK is the bridge to verifier economy.

## Artifacts

| Artifact                    | Path                                                              |
|-----------------------------|-------------------------------------------------------------------|
| Rust implementation         | `crates/franken-node/src/connector/verifier_sdk.rs`               |
| JSON Schema                 | `spec/evidence_bundle_schema.json`                                |
| Spec contract               | `docs/specs/section_10_12/bd-3c2_contract.md`                     |
| Gate script                 | `scripts/check_verifier_sdk.py`                                   |
| Test file                   | `tests/test_check_verifier_sdk.py`                                |
| Verification evidence       | `artifacts/section_10_12/bd-3c2/verification_evidence.json`       |
| Verification summary        | `artifacts/section_10_12/bd-3c2/verification_summary.md`          |
