# DGIS Release Claim Gate Contract (bd-38yt)

## Purpose

The DGIS release claim gate blocks topology-security claims when DGIS
performance budgets are exceeded, degradation signals are missing, or signed
evidence artifacts are incomplete.

## Designated Claims

1. `DGIS-CLAIM-001` - Graph ingestion meets p95/p99 latency budgets at target
   ecosystem scale.
2. `DGIS-CLAIM-002` - Metric computation meets p95/p99 budgets and emits
   deterministic degradation signals on violations.
3. `DGIS-CLAIM-003` - Contagion simulation remains within p95/p99 budgets for
   documented graph complexity.
4. `DGIS-CLAIM-004` - Economic ranking remains within p95/p99 budgets and has a
   complete signed evidence chain for release claims.

Each designated claim MUST include:
- `target_scale` object:
  - `nodes` (integer > 0)
  - `edges` (integer > 0)
  - `max_articulation_points` (integer >= 0)
- `budget_p95_ms` (float > 0)
- `measured_p95_ms` (float >= 0)
- `budget_p99_ms` (float > 0)
- `measured_p99_ms` (float >= 0)
- `degradation_signal` (string prefixed with `DGIS-PERF-`)
- `required_signed_evidence` (integer >= 0)
- `signed_evidence_present` (integer >= 0)
- `evidence_refs` (non-empty list of repository-relative artifact paths)

## Gate Decision Rules

- Claim-level decision:
  - PASS when:
    - `measured_p95_ms <= budget_p95_ms`
    - `measured_p99_ms <= budget_p99_ms`
    - `signed_evidence_present >= required_signed_evidence`
    - all `evidence_refs` exist
  - FAIL otherwise.
- Release-level decision:
  - `allow` when all designated claims PASS.
  - `block` when any designated claim FAILS.

## Machine-Readable Output Contract

Canonical report path:
- `artifacts/10.20/dgis_release_gate_report.json`

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

- `DGIS-PERF-001`: Gate evaluation started.
- `DGIS-PERF-002`: All designated claims satisfied; release allowed.
- `DGIS-PERF-003`: One or more latency budgets exceeded.
- `DGIS-PERF-004`: Signed evidence completeness check failed; release blocked.
- `DGIS-PERF-005`: Degradation signal emitted for over-budget computation.
- `DGIS-PERF-ERR-SIGNATURE`: Signature or canonical payload mismatch.
- `DGIS-PERF-ERR-INPUT`: Report schema/content invalid.

## Determinism Requirement

Running the gate repeatedly on identical input MUST produce the same:
- claim decisions
- `summary.release_decision`
- `signing.canonical_payload_sha256`
- `signing.signature`
