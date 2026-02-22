# ATC Release Claim Gate Contract (bd-11rz)

## Purpose

The ATC release claim gate blocks releases when designated ecosystem-level trust
claims do not include required ATC coverage and provenance evidence.

## Designated Claims

1. `ATC-CLAIM-001` - Federated threat-intelligence claim includes required
   ATC coverage across participating cohorts.
2. `ATC-CLAIM-002` - Published ecosystem metric includes verifier-backed
   coverage for the declared ATC slice.
3. `ATC-CLAIM-003` - Public trust claim includes signed provenance artifacts
   that can be independently replayed.

Each designated claim MUST include:
- `required_coverage_ratio` (0.0..1.0)
- `coverage_ratio` (0.0..1.0)
- `required_provenance_artifacts` (integer >= 0)
- `provenance_artifacts_present` (integer >= 0)
- `evidence_refs` (non-empty list of repository-relative artifact paths)

## Gate Decision Rules

- Claim-level decision:
  - PASS when `coverage_ratio >= required_coverage_ratio`,
    `provenance_artifacts_present >= required_provenance_artifacts`,
    and all evidence references exist.
  - FAIL otherwise.
- Release-level decision:
  - `allow` when all designated claims PASS.
  - `block` when any designated claim FAILS.

## Machine-Readable Output Contract

Canonical report path:
- `artifacts/10.19/atc_release_gate_report.json`

Required top-level fields:
- `bead_id`
- `generated_at_utc`
- `gate_version`
- `public_key_id`
- `signature_algorithm`
- `designated_claims`
- `summary`
- `signing`
- `events`

`summary` MUST include:
- `total_claims`
- `passed_claims`
- `failed_claims`
- `release_decision`

## Signing + External Verification

The report uses deterministic canonical signing metadata:
- `signing.canonical_payload_sha256`
- `signing.signature`

Canonical payload:
- JSON object with only: `bead_id`, `generated_at_utc`, `gate_version`,
  `public_key_id`, `signature_algorithm`, `designated_claims`, `summary`.
- Serialized with sorted keys and compact separators.
- SHA-256 digest becomes `canonical_payload_sha256`.
- Signature value is deterministic SHA-256 over
  `"{public_key_id}:{canonical_payload_sha256}"`.

External verifiers can independently recompute both values from report content
without private participant data.

## Event Codes

- `ATC-RELEASE-001`: Gate evaluation started.
- `ATC-RELEASE-002`: All designated claims satisfied; release allowed.
- `ATC-RELEASE-003`: One or more designated claims failed; release blocked.
- `ATC-RELEASE-ERR-SIGNATURE`: Signature or canonical payload mismatch.
- `ATC-RELEASE-ERR-INPUT`: Report schema/content invalid.

## Determinism Requirement

Running the gate repeatedly on identical input MUST produce the same:
- claim decisions
- `summary.release_decision`
- `signing.canonical_payload_sha256`
- `signing.signature`
