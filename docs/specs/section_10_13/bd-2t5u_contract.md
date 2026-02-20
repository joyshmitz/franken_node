# bd-2t5u: Predictive Pre-staging Engine

## Purpose

Pre-stage high-probability offline artifacts to improve offline coverage. Budget limits prevent prefetch storms. Prediction quality is measured and reported.

## Invariants

- **INV-PSE-BUDGET**: Total pre-staged bytes never exceed the configured budget.
- **INV-PSE-COVERAGE**: Pre-staging improves coverage over the baseline (no pre-staging).
- **INV-PSE-DETERMINISTIC**: Same history + same model → same pre-stage decisions.
- **INV-PSE-QUALITY**: Prediction precision and recall are measured and reported.

## Types

### PrestageConfig

Budget limit (max_bytes), probability threshold, max artifacts per cycle.

### ArtifactCandidate

An artifact eligible for pre-staging: artifact_id, size_bytes, predicted_probability.

### PrestageDecision

Decision record: artifact_id, staged (bool), reason, budget_remaining.

### PrestageReport

Coverage report: total_candidates, staged_count, skipped_count, budget_used, precision, recall.

### PrestageEngine

Engine that accepts candidates + config, produces decisions within budget.

## Functions

- `evaluate_candidates(candidates, config, trace_id, timestamp)` → `(Vec<PrestageDecision>, PrestageReport)`
- `validate_config(config)` → `Result<(), PrestageError>`
- `measure_quality(decisions, actual_needed)` → quality metrics

## Error Codes

- `PSE_BUDGET_EXCEEDED` — attempted to stage beyond budget
- `PSE_INVALID_CONFIG` — config has invalid values
- `PSE_NO_CANDIDATES` — no candidates provided
- `PSE_THRESHOLD_INVALID` — probability threshold out of [0,1]
