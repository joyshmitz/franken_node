# bd-1jmq Contract: EV Score and Tier

## Purpose

Define a mandatory, machine-verifiable contract field named
`change_summary.ev_score_and_tier` for subsystem proposals.

This field ensures each major subsystem change includes an explicit
Extension Verification (EV) score and a tier classification that quantifies
the verification posture across multiple dimensions and maps the weighted
aggregate to a canonical tier (T0 through T4).

## Section

11 — Evidence and Decision Contracts

## Contract Field

Path:
- `change_summary.ev_score_and_tier`

Required sub-fields:
1. `ev_score` (object) — weighted aggregate of verification dimensions
2. `tier` (string in `{T0, T1, T2, T3, T4}`)
3. `dimension_scores` (object with per-dimension breakdown)
4. `rationale` (non-empty string)

### ev_score

The EV score is a normalized value in the range [0, 100] computed as a
weighted aggregate of verification dimension scores.

Formula:
```
ev_score = sum(dimension_weight[d] * dimension_score[d] for d in dimensions)
```

Each dimension score is a float in [0.0, 1.0]. Weights are positive and
sum to 1.0.

### Verification Dimensions

| Dimension | Weight | Description |
|-----------|--------|-------------|
| code_review | 0.20 | Peer review coverage and depth |
| test_coverage | 0.20 | Test suite breadth and pass rate |
| security_audit | 0.25 | Security audit completeness |
| supply_chain | 0.15 | Supply chain provenance verification |
| conformance | 0.20 | Conformance to protocol and spec contracts |

Weights MUST sum to exactly 1.0 (tolerance: 1e-9).

### dimension_scores

Each entry MUST contain:
- `score` (float in [0.0, 1.0])
- `evidence_ref` (non-empty string referencing verification artifact)
- `assessed_at` (ISO 8601 timestamp)

### tier

Tier classification based on the composite EV score:

| Tier | Label | Score Range | Description |
|------|-------|-------------|-------------|
| T0 | Unverified | 0-19 | No verification evidence |
| T1 | Self-declared | 20-39 | Publisher self-assessment only |
| T2 | Community-reviewed | 40-59 | Community review completed |
| T3 | Audited | 60-79 | Independent security audit passed |
| T4 | Formally-verified | 80-100 | Formal verification or equivalent rigor |

The tier MUST be consistent with the computed EV score.

### rationale

A non-empty string explaining the scoring decision, including:
- Key verification dimensions that drove the score.
- Evidence sources referenced for each dimension.
- Any mitigating factors that influenced the assessment.

## Upgrade Path

Tier transitions follow strict requirements:

| Transition | Requirements |
|------------|-------------|
| T0 -> T1 | Self-assessment submitted with evidence references |
| T1 -> T2 | Community review completed by at least 2 independent reviewers |
| T2 -> T3 | Independent security audit passed within last 12 months |
| T3 -> T4 | Formal verification proof or equivalent rigor demonstrated |

Upgrades MUST be recorded with an EVS-003 event.

## Downgrade Triggers

A tier downgrade warning (EVS-004) is emitted when:
- Security audit expires (>12 months since last audit)
- Active security advisory filed against the subsystem
- Conformance test failure detected in CI
- Supply chain provenance verification fails

Downgrades are applied automatically when the recomputed EV score
falls below the current tier threshold.

## Trust Card Integration

The EV score and tier MUST be displayed in trust cards:
- Human-readable tier label (e.g., "T3 — Audited")
- Numeric EV score (0-100)
- Per-dimension breakdown available on demand
- Trend indicator (improving / stable / declining)

## Enforcement

Validator:
- `scripts/check_ev_score.py`

Unit tests:
- `tests/test_check_ev_score.py`

## Event Codes

| Code | Severity | Description |
|------|----------|-------------|
| EVS-001 | info | EV score computed for subsystem |
| EVS-002 | info | Tier assigned based on computed score |
| EVS-003 | info | Tier upgraded after verification improvement |
| EVS-004 | warning | Tier downgrade warning — verification gap detected |

## Invariants

| ID | Rule |
|----|------|
| INV-EVS-COMPUTE | EV score is a weighted aggregate of dimension scores, normalized to [0, 100] |
| INV-EVS-TIER | Tier classification is consistent with EV score thresholds |
| INV-EVS-UPGRADE | Tier upgrades require documented evidence for target tier requirements |
| INV-EVS-DOWNGRADE | Tier downgrades are triggered by expired audit, security advisory, or failed conformance |

## Acceptance Criteria

1. EV score field is required on all subsystem change proposals.
2. Dimension scores are floats in range [0.0, 1.0].
3. Dimension weights sum to 1.0.
4. Composite EV score is in range [0, 100].
5. Tier classification matches EV score thresholds (T0: 0-19, T1: 20-39, T2: 40-59, T3: 60-79, T4: 80-100).
6. Rationale is non-empty and references evidence.
7. Upgrade path documented with per-transition requirements.
8. Downgrade triggers enumerated and machine-enforceable.
9. All four event codes (EVS-001 through EVS-004) emitted at appropriate points.
10. All four invariants (INV-EVS-COMPUTE, INV-EVS-TIER, INV-EVS-UPGRADE, INV-EVS-DOWNGRADE) are machine-verifiable.
11. Trust card integration displays tier label and numeric score.
12. Validator rejects proposals with missing or invalid EV scores.
