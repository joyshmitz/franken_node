# bd-3h1g Contract: Benchmark Specs/Harness/Datasets/Scoring Publication

## Goal

Publish a deterministic benchmark package that external parties can run and
score without hidden assumptions.

## Quantified Invariants

- `INV-BSP-TRACK-COVERAGE`: Benchmark package defines exactly 6 required tracks:
  - `compatibility_correctness`
  - `security_trust`
  - `performance_under_hardening`
  - `containment_revocation_latency`
  - `replay_determinism`
  - `adversarial_resilience`
- `INV-BSP-TRACK-WEIGHTS`: Track weights are strictly positive and sum to `1.0`.
- `INV-BSP-HARNESS-REPRO`: Harness defines deterministic run controls:
  - `determinism_replays >= 3`
  - `warmup_runs >= 1`
  - `measured_runs >= 5`
  - fixed seed policy + isolated execution mode
- `INV-BSP-DATASET-INTEGRITY`: Dataset catalog covers all required tracks with:
  - unique dataset ids
  - per-dataset integrity hash (`sha256`, 64 lowercase hex chars)
  - `records >= 1000` per dataset
- `INV-BSP-SCORING-FORMULA`: Scoring formula is explicit and machine-parseable:
  - `aggregate_score = sum(weight_i * score_i)`
  - `minimum_track_score = 0.75`
  - `minimum_overall_score = 0.85`
- `INV-BSP-QUALITY-GATES`: Sample score payload must satisfy both gates:
  - all track scores `>= minimum_track_score`
  - overall weighted score `>= minimum_overall_score`
- `INV-BSP-DETERMINISM`: Reordering track entries does not change the weighted
  score or gate verdict.
- `INV-BSP-ADVERSARIAL`: Adversarial perturbation reducing one track below
  `minimum_track_score` must flip verdict to FAIL.

## Required Data Contract

`artifacts/14/benchmark_specs_package.json` must include:

- Metadata:
  - `bead_id`
  - `generated_at_utc`
  - `spec_version`
  - `trace_id`
- Benchmark tracks (`benchmark_tracks[]`):
  - `track_id`
  - `display_name`
  - `weight`
  - `metric_ids` (list, at least 2 entries)
  - `pass_threshold`
- Harness (`harness`):
  - `runner_command`
  - `seed_policy`
  - `determinism_replays`
  - `warmup_runs`
  - `measured_runs`
  - `isolation_mode`
- Dataset catalog (`datasets[]`):
  - `dataset_id`
  - `track_id`
  - `source_uri`
  - `records`
  - `sha256`
  - `license`
- Scoring formula (`scoring_formula`):
  - `normalization`
  - `aggregate_formula`
  - `minimum_track_score`
  - `minimum_overall_score`
  - `hard_fail_conditions` (list)
- Sample scoring payload:
  - `sample_scores`
  - `sample_overall_score`
- `event_codes` list.

## Required Scenarios

1. **Pass scenario**: contract + package validate and score gates pass.
2. **Coverage-fail scenario**: missing required track or dataset fails.
3. **Weight-fail scenario**: non-unit weight sum fails.
4. **Track-threshold fail**: one track score below `0.75` fails.
5. **Determinism scenario**: reordered tracks keep same score/verdict.
6. **Adversarial scenario**: perturbation below threshold flips to FAIL.

## Structured Event Codes

- `BSP-001`: Benchmark package loaded.
- `BSP-002`: Contract fields/invariants validated.
- `BSP-003`: Scoring formula validated.
- `BSP-004`: Determinism check passed.
- `BSP-005`: Adversarial perturbation check executed.
- `BSP-006`: Final verdict emitted.

All events include stable `trace_id`.

## Gate Decision Flow

1. Validate contract and package schema presence.
2. Validate track coverage, weights, harness controls, and dataset integrity.
3. Validate scoring formula + sample score consistency.
4. Execute determinism and adversarial checks.
5. Emit structured events and deterministic PASS/FAIL verdict.
