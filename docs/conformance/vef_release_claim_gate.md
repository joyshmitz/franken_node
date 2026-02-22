# VEF Release Claim Gate Contract (bd-3lzk)

## Purpose

The VEF release claim gate blocks releases when designated high-impact
security/compliance claims do not have sufficient VEF-backed evidence coverage.

## Designated Claims

1. `VEF-CLAIM-001` - Filesystem policy compliance is provably enforced.
2. `VEF-CLAIM-002` - Secret access is authorized and evidence-backed.
3. `VEF-CLAIM-003` - High-risk runtime actions produce verifiable receipts.

Each designated claim MUST include:
- `required_coverage_ratio` (0.0..1.0)
- `coverage_ratio` (0.0..1.0)
- `evidence_refs` (non-empty list of repository-relative artifact paths)

## Gate Decision Rules

- Claim-level decision:
  - PASS when `coverage_ratio >= required_coverage_ratio` and all evidence
    references exist.
  - FAIL otherwise.
- Release-level decision:
  - `allow` when all designated claims PASS.
  - `block` when any designated claim FAILS.

## Machine-Readable Output Contract

Canonical report path:
- `artifacts/10.18/vef_release_gate_report.json`

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
without private data.

## Event Codes

- `VEF-RELEASE-001`: Gate evaluation started.
- `VEF-RELEASE-002`: All designated claims satisfied; release allowed.
- `VEF-RELEASE-003`: One or more designated claims failed; release blocked.
- `VEF-RELEASE-ERR-SIGNATURE`: Signature or canonical payload mismatch.
- `VEF-RELEASE-ERR-INPUT`: Report schema/content invalid.

## Determinism Requirement

Running the gate repeatedly on identical input MUST produce the same:
- claim decisions
- `summary.release_decision`
- `signing.canonical_payload_sha256`
- `signing.signature`
