# bd-whxp Contract: >=2 Independent Replications Gate

## Goal

Enforce a hard gate requiring at least `2` independent external replications of
headline section-13 claims before release readiness.

## Quantified Invariants

- `INV-IRG-MIN-REPLICATIONS`: `independent_replications_passing >= 2`.
- `INV-IRG-REQUIRED-CLAIMS`: Every replication validates all required claims:
  - `migration_velocity_3x`
  - `compromise_reduction_10x`
  - `replay_coverage_100pct`
- `INV-IRG-INDEPENDENCE`: Independent replications must come from distinct
  organizations and use distinct evaluator identities.
- `INV-IRG-CONFLICT-DISCLOSURE`: Replications marked independent must have
  `disclosed_funding_conflict=false`.
- `INV-IRG-EVIDENCE-LINKS`: Every claim result includes a non-empty
  `evidence_uri`.
- `INV-IRG-DETERMINISM`: Reordering replication records does not change
  computed passing-independent count or verdict.
- `INV-IRG-ADVERSARIAL`: Adversarial perturbation reducing one independent pass
  must flip verdict to FAIL.

## Required Data Contract

`artifacts/13/independent_replication_report.json` must include:

- Metadata:
  - `bead_id`
  - `generated_at_utc`
  - `trace_id`
  - `required_minimum_replications`
  - `required_claims[]`
- Replication entries (`replications[]`) with required fields:
  - `replication_id`
  - `organization`
  - `independent`
  - `executed_at_utc`
  - `source_url`
  - `source_commit`
  - `evaluator_hash`
  - `environment_fingerprint`
  - `disclosed_funding_conflict`
  - `claim_results` object keyed by required claims, each containing:
    - `pass`
    - `evidence_uri`
    - `measured_value`
- Summary:
  - `replication_count`
  - `independent_replication_count`
  - `independent_replications_passing`
  - `verdict`

## Determinism and Adversarial Checks

- Gate recomputes independent/passing counts from raw replication records.
- Gate verifies summary values match recomputed values.
- Gate recomputes verdict on reordered entries and requires identical result.
- Gate applies adversarial perturbation (demote one independent pass) and
  requires verdict to flip to FAIL.

## Required Scenarios

1. **Pass scenario**: at least two independent replications pass all claims.
2. **Coverage-fail scenario**: any replication missing required claim result
   fails.
3. **Independence-fail scenario**: independent replications from same org or
   shared evaluator hash fail.
4. **Claim-fail scenario**: independent replication with a failed claim does not
   count toward the threshold.
5. **Determinism scenario**: reordered inputs produce same verdict.
6. **Adversarial scenario**: demoting one independent pass flips verdict.

## Structured Event Codes

- `IRG-001`: Replication report loaded.
- `IRG-002`: Required claims and schema validated.
- `IRG-003`: Independence checks validated.
- `IRG-004`: Threshold gate passed (`>=2` independent passing replications).
- `IRG-005`: Threshold gate failed (`<2` independent passing replications).
- `IRG-006`: Determinism/adversarial checks executed.

All events include stable `trace_id`.

## Gate Decision Flow

1. Load and validate report schema and required claims.
2. Validate replication entries, timestamps, and claim result completeness.
3. Validate independence constraints and conflict disclosure.
4. Recompute independent passing count and threshold verdict.
5. Verify summary consistency.
6. Execute determinism and adversarial checks.
7. Emit structured events and deterministic PASS/FAIL verdict.
