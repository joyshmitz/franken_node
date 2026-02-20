# bd-jxgt: Execution Planner Scorer

## Purpose

Score execution candidates using latency, risk, and capability factors with explicit weights. Output is deterministic: identical inputs produce identical scores and rankings. Tie-breakers are explicit and tested.

## Invariants

- **INV-EPS-DETERMINISTIC**: Same candidates + same weights → identical ranking.
- **INV-EPS-TIEBREAK**: Ties are broken by explicit, documented rule (lexicographic device_id).
- **INV-EPS-EXPLAINABLE**: Every scored candidate includes per-factor breakdown.
- **INV-EPS-REJECT-INVALID**: Invalid weight configurations are rejected with a classified error.

## Types

### ScoringWeights

Configurable factor weights: latency_weight, risk_weight, capability_weight (all f64, must sum > 0).

### CandidateInput

Input for scoring: device_id, estimated_latency_ms, risk_score (0.0–1.0), capability_match_ratio (0.0–1.0).

### ScoredCandidate

Output: device_id, total_score, factor_breakdown (latency_component, risk_component, capability_component), rank.

### PlannerDecision

Full decision record: ranked candidates, weights used, trace_id, timestamp.

### ExecutionScorer

Stateless scorer: `score_candidates(candidates, weights)` → `PlannerDecision`.

## Functions

- `score_candidates(candidates, weights, trace_id, timestamp)` → `Result<PlannerDecision, ScorerError>`
- `validate_weights(weights)` → `Result<(), ScorerError>`

## Error Codes

- `EPS_INVALID_WEIGHTS` — weights sum to zero or contain negatives
- `EPS_NO_CANDIDATES` — empty candidate list
- `EPS_INVALID_INPUT` — candidate has out-of-range values
- `EPS_SCORE_OVERFLOW` — computed score exceeds representable range
