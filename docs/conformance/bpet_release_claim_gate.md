# BPET Release Claim Gate Contract (bd-3v9l)

## Purpose

The BPET release claim gate blocks predictive pre-compromise trajectory claims
when scoring/storage budgets are exceeded, degradation signaling is missing, or
signed calibration/provenance artifacts are incomplete.

## Designated Claims

1. `BPET-CLAIM-001` - Trajectory scoring latency stays within p95/p99 budgets
   at target phenotype scale.
2. `BPET-CLAIM-002` - Drift/regime analysis latency stays within p95/p99
   budgets and emits deterministic degradation signals on violations.
3. `BPET-CLAIM-003` - Longitudinal lineage persistence stays within declared
   storage-overhead budget.
4. `BPET-CLAIM-004` - Predictive release claim package includes signed
   calibration and provenance artifacts sufficient for independent validation.

Each designated claim MUST include:
- `target_scale` object:
  - `phenotypes` (integer > 0)
  - `trajectories` (integer > 0)
  - `history_days` (integer > 0)
- `budget_p95_ms` (float > 0)
- `measured_p95_ms` (float >= 0)
- `budget_p99_ms` (float > 0)
- `measured_p99_ms` (float >= 0)
- `budget_storage_mb` (float > 0)
- `measured_storage_mb` (float >= 0)
- `degradation_signal` (string prefixed with `BPET-PERF-`)
- `required_calibration_artifacts` (integer >= 0)
- `calibration_artifacts_present` (integer >= 0)
- `required_signed_provenance` (integer >= 0)
- `signed_provenance_present` (integer >= 0)
- `evidence_refs` (non-empty list of repository-relative artifact paths)

## Gate Decision Rules

- Claim-level decision:
  - PASS when:
    - `measured_p95_ms <= budget_p95_ms`
    - `measured_p99_ms <= budget_p99_ms`
    - `measured_storage_mb <= budget_storage_mb`
    - `calibration_artifacts_present >= required_calibration_artifacts`
    - `signed_provenance_present >= required_signed_provenance`
    - all `evidence_refs` exist
  - FAIL otherwise.
- Release-level decision:
  - `allow` when all designated claims PASS.
  - `block` when any designated claim FAILS.

## Machine-Readable Output Contract

Canonical report path:
- `artifacts/10.21/bpet_release_gate_report.json`

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
without private phenotype data.

## Event Codes

- `BPET-PERF-001`: Gate evaluation started.
- `BPET-PERF-002`: All designated claims satisfied; release allowed.
- `BPET-PERF-003`: One or more latency/storage budgets exceeded.
- `BPET-PERF-004`: Calibration/provenance completeness check failed; release blocked.
- `BPET-PERF-005`: Degradation signal emitted for over-budget computation.
- `BPET-PERF-ERR-SIGNATURE`: Signature or canonical payload mismatch.
- `BPET-PERF-ERR-INPUT`: Report schema/content invalid.

## Determinism Requirement

Running the gate repeatedly on identical input MUST produce the same:
- claim decisions
- `summary.release_decision`
- `signing.canonical_payload_sha256`
- `signing.signature`
