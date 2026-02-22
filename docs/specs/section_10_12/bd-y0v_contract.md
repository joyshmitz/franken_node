# bd-y0v Contract: Operator Intelligence Recommendation Engine

**Bead:** bd-y0v
**Section:** 10.12 (Frontier Programs — Operator Intelligence)
**Status:** Active
**Owner:** SilverMeadow

## Purpose

Implement an operator intelligence recommendation engine that produces
expected-loss-scored recommendations with rollback proofs, deterministic replay
artifacts, and a full audit trail. Operators receive quantified risk estimates,
concrete action plans, and cryptographic rollback guarantees for every
recommendation.

## Configuration

| Field                         | Type   | Default | Description                              |
|-------------------------------|--------|---------|------------------------------------------|
| `max_recommendations`         | usize  | 10      | Max recommendations per query            |
| `confidence_threshold`        | f64    | 0.5     | Min confidence to emit a recommendation  |
| `risk_budget`                 | f64    | 100.0   | Max cumulative expected-loss budget       |
| `degraded_confidence_penalty` | f64    | 0.5     | Confidence multiplier in degraded mode   |

## Event Codes

| Code    | Severity | Structured Log Event                       | Description                                |
|---------|----------|--------------------------------------------|--------------------------------------------|
| OIR-001 | INFO     | `oi.recommendation_generated`              | Recommendation generated with score        |
| OIR-002 | INFO     | `oi.recommendation_accepted`               | Recommendation accepted by operator        |
| OIR-003 | INFO     | `oi.recommendation_rejected`               | Recommendation rejected by operator        |
| OIR-004 | INFO     | `oi.action_executed`                        | Recommended action executed                |
| OIR-005 | INFO     | `oi.rollback_proof_created`                | Rollback proof generated                   |
| OIR-006 | INFO     | `oi.rollback_proof_verified`               | Rollback proof verified successfully       |
| OIR-007 | INFO     | `oi.rollback_executed`                      | Rollback executed to restore prior state   |
| OIR-008 | INFO     | `oi.replay_artifact_created`               | Deterministic replay artifact created      |
| OIR-009 | WARN     | `oi.degraded_mode_entered`                 | Degraded mode: missing input data          |
| OIR-010 | WARN     | `oi.degraded_mode_warning`                 | Recommendation has degraded data quality   |

## Error Codes

| Code                          | Description                               |
|-------------------------------|-------------------------------------------|
| ERR_OIR_INVALID_CONFIG        | Configuration parameter out of range      |
| ERR_OIR_NO_CONTEXT            | Operator context missing or invalid       |
| ERR_OIR_SCORE_OVERFLOW        | Expected-loss exceeds risk budget         |
| ERR_OIR_ROLLBACK_FAILED       | Rollback proof verification failed        |
| ERR_OIR_REPLAY_MISMATCH       | Replay produced different outcome         |
| ERR_OIR_DEGRADED              | Data source unavailable (degraded mode)   |

## Invariants

- **INV-OIR-DETERMINISTIC** — Identical inputs produce identical scores and
  recommendation rankings across runs.
- **INV-OIR-ROLLBACK-SOUND** — Every executed recommendation has a verifiable
  rollback proof; applying the rollback restores pre-action state hash.
- **INV-OIR-BUDGET** — The cumulative expected-loss of accepted recommendations
  never exceeds the configured risk budget.
- **INV-OIR-AUDIT** — Every generated recommendation (accepted or rejected)
  is recorded in the audit trail with timestamp and context fingerprint.

## Types

### RecommendationEngine

Core engine that accepts operator context and produces ranked recommendations.

### Recommendation

| Field               | Type    | Description                              |
|---------------------|---------|------------------------------------------|
| `id`                | String  | Unique recommendation ID                 |
| `action`            | String  | Action description                       |
| `expected_loss`     | f64     | Quantified downside (normalized risk)    |
| `confidence`        | f64     | Confidence interval [0.0, 1.0]           |
| `priority`          | u32     | Priority rank (1 = highest)              |
| `prerequisites`     | Vec     | List of prerequisite check IDs           |
| `estimated_time_ms` | u64     | Estimated execution time                 |

### OperatorContext

| Field                | Type    | Description                             |
|----------------------|---------|-----------------------------------------|
| `compatibility_pass` | f64     | Compatibility test pass rate [0.0, 1.0] |
| `migration_success`  | f64     | Migration success rate [0.0, 1.0]       |
| `trust_valid`        | f64     | Trust artifact validity rate [0.0, 1.0] |
| `error_rate`         | f64     | Current error rate [0.0, 1.0]           |
| `pending_ops`        | usize   | Pending operations count                |
| `active_alerts`      | usize   | Active alert count                      |

### RollbackProof

| Field               | Type     | Description                             |
|---------------------|----------|-----------------------------------------|
| `pre_state_hash`    | [u8; 32] | Content-addressed pre-action state      |
| `action_spec`       | String   | Deterministic command sequence          |
| `post_state_hash`   | [u8; 32] | Expected post-action state              |
| `rollback_spec`     | String   | Rollback command sequence               |

### ReplayArtifact

| Field               | Type     | Description                             |
|---------------------|----------|-----------------------------------------|
| `recommendation_id` | String   | ID of the recommendation replayed       |
| `input_context`     | String   | Serialized input context                |
| `action_executed`   | String   | Action that was executed                |
| `outcome`           | String   | Observed outcome                        |
| `rollback_proof`    | bytes    | Embedded rollback proof                 |

## Acceptance Criteria

1. `RecommendationEngine` in `crates/franken-node/src/connector/operator_intelligence.rs`
   with context-driven recommendation generation.
2. Expected-loss scoring is deterministic: same inputs produce identical scores.
3. Rollback proofs are generated and verified round-trip for executed recommendations.
4. Deterministic replay artifacts capture full input-to-output trace.
5. Audit trail records every recommendation with timestamp and context fingerprint.
6. Degraded mode widens confidence intervals and emits data-quality warnings.
7. >= 30 unit tests covering all invariants.
8. Verification script `scripts/check_operator_intelligence.py` passes all checks.
9. Evidence artifacts in `artifacts/section_10_12/bd-y0v/`.

## Dependencies

- **bd-5si** (trust fabric) — trust state feeds risk scoring.
- **Section 10.2** (compatibility core) — pass rates feed scoring.
- **Section 10.3** (migration system) — migration success rates feed scoring.

## File Layout

```
docs/specs/section_10_12/bd-y0v_contract.md   (this file)
docs/policy/operator_intelligence.md
crates/franken-node/src/connector/operator_intelligence.rs
scripts/check_operator_intelligence.py
tests/test_check_operator_intelligence.py
artifacts/section_10_12/bd-y0v/verification_evidence.json
artifacts/section_10_12/bd-y0v/verification_summary.md
```
