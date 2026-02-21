# Policy: EV Score and Tier Classification

**Bead:** bd-1jmq
**Section:** 11 — Evidence and Decision Contracts
**Status:** Active
**Last reviewed:** 2026-02-20

---

## 1. Overview

The Extension Verification (EV) score quantifies the verification posture
of a subsystem change. It aggregates evidence across five verification
dimensions into a single normalized score (0-100) and maps that score to
one of five tiers (T0 through T4).

Every subsystem change proposal MUST include a valid
`change_summary.ev_score_and_tier` field. Proposals without this field
are rejected at the gate.

## 2. EV Score Formula

The EV score is computed as a weighted aggregate of dimension scores:

```
ev_score = round(100 * sum(weight[d] * score[d] for d in dimensions))
```

Each dimension score is a float in [0.0, 1.0]. Weights are positive reals
that sum to exactly 1.0.

### 2.1 Verification Dimensions and Weights

| Dimension | Weight | What It Measures |
|-----------|--------|------------------|
| code_review | 0.20 | Peer review coverage: fraction of changed lines reviewed by independent reviewers. |
| test_coverage | 0.20 | Test suite breadth: statement coverage, branch coverage, and pass rate. |
| security_audit | 0.25 | Security audit completeness: fraction of threat vectors with documented mitigation. |
| supply_chain | 0.15 | Supply chain provenance: SLSA level, dependency trust, artifact attestation. |
| conformance | 0.20 | Protocol conformance: fraction of spec contracts with passing verification. |

### 2.2 Normalization

- Dimension scores MUST be in [0.0, 1.0].
- Weights MUST be positive and sum to 1.0 (tolerance: 1e-9).
- The composite EV score is rounded to the nearest integer in [0, 100].

### 2.3 Example Calculation

```
code_review    = 0.85   weight = 0.20   contribution = 17.0
test_coverage  = 0.90   weight = 0.20   contribution = 18.0
security_audit = 0.70   weight = 0.25   contribution = 17.5
supply_chain   = 0.60   weight = 0.15   contribution =  9.0
conformance    = 0.80   weight = 0.20   contribution = 16.0
                                        -----------------
                                        ev_score = 77.5 -> 78 (T3)
```

## 3. Tier Thresholds

| Tier | Label | Score Range | Description |
|------|-------|-------------|-------------|
| T0 | Unverified | 0-19 | No meaningful verification evidence. |
| T1 | Self-declared | 20-39 | Publisher self-assessment only, no independent review. |
| T2 | Community-reviewed | 40-59 | Community review completed by 2+ independent parties. |
| T3 | Audited | 60-79 | Independent security audit passed within 12 months. |
| T4 | Formally-verified | 80-100 | Formal verification or equivalent mathematical rigor. |

Tier boundaries are inclusive on the lower bound and inclusive on the upper
bound. A score of exactly 80 maps to T4.

## 4. Upgrade Path

Tier upgrades require the subsystem to meet all requirements of the
target tier. The following table lists per-transition requirements:

| Transition | Requirements |
|------------|-------------|
| T0 -> T1 | Self-assessment submitted. At least one evidence reference per dimension. |
| T1 -> T2 | Community review completed by at least 2 independent reviewers. Review artifacts linked. |
| T2 -> T3 | Independent security audit passed within last 12 months. Audit report artifact stored. |
| T3 -> T4 | Formal verification proof submitted. Proof covers all invariants. Machine-checkable artifact. |

Upgrade events are recorded with event code **EVS-003**.

### 4.1 Upgrade Evidence

Each upgrade transition MUST produce:
- An EVS-003 event with the previous tier, new tier, and evidence references.
- Updated `dimension_scores` entries with fresh `assessed_at` timestamps.
- A human-readable rationale summarizing the verification improvement.

## 5. Downgrade Triggers

A tier downgrade warning (**EVS-004**) is emitted when any of the
following conditions is detected:

| Trigger | Detection Method | Grace Period |
|---------|-----------------|--------------|
| Expired audit | Security audit older than 12 months | 30 days |
| Security advisory | Active CVE or advisory filed against subsystem | Immediate |
| Failed conformance | Conformance test failure in CI pipeline | 7 days |
| Supply chain failure | Provenance verification fails for dependency | 7 days |
| Review coverage drop | Code review coverage below threshold for 2 consecutive releases | 14 days |

After the grace period expires, the subsystem's EV score is recomputed.
If the new score falls below the current tier threshold, the tier is
automatically downgraded.

### 5.1 Downgrade Process

1. EVS-004 warning emitted with trigger details.
2. Grace period countdown begins.
3. If trigger not resolved within grace period, dimension scores recalculated.
4. New EV score computed from updated dimension scores.
5. If new score < current tier lower bound, tier downgraded.
6. EVS-002 event emitted with new tier assignment.

## 6. Display and Trust Card Integration

The EV score and tier are displayed in trust cards:

- **Tier badge**: Human-readable label, e.g., "T3 — Audited".
- **Numeric score**: Integer 0-100.
- **Dimension breakdown**: Per-dimension scores available on hover/expand.
- **Trend indicator**: Computed from last 3 assessments:
  - "improving" if latest score > previous by >= 5 points.
  - "declining" if latest score < previous by >= 5 points.
  - "stable" otherwise.
- **Last assessed**: ISO 8601 timestamp of most recent computation.

## 7. Governance

### 7.1 Weight Adjustments

Dimension weights may be adjusted through a formal governance process:

1. Proposal submitted as a bead with rationale and impact analysis.
2. At least 2 reviewers from different teams approve the change.
3. Impact analysis shows how existing tier assignments would shift.
4. 14-day notice period before weights take effect.
5. All existing EV scores recomputed under new weights.

### 7.2 Appeal Process

Subsystem owners may appeal a tier assignment or downgrade:

1. Appeal filed within 7 days of assignment/downgrade.
2. Appellant provides additional evidence supporting higher tier.
3. Review committee of 3 evaluates evidence within 5 business days.
4. Decision is final and recorded as an EVS-003 (if upgraded) or
   EVS-002 (if current tier confirmed).

### 7.3 Audit Trail

All EV score computations, tier assignments, upgrades, and downgrades
are recorded in an immutable audit log with:
- Timestamp (ISO 8601).
- Event code (EVS-001 through EVS-004).
- Input dimension scores and weights.
- Computed score and assigned tier.
- Actor identity (automated system or human reviewer).

## 8. Event Codes

| Code | Severity | Emitted When |
|------|----------|-------------|
| EVS-001 | info | EV score computed for a subsystem |
| EVS-002 | info | Tier assigned or reassigned based on score |
| EVS-003 | info | Tier upgraded after meeting target requirements |
| EVS-004 | warning | Downgrade trigger detected, grace period started |

## 9. Invariants

| ID | Rule |
|----|------|
| INV-EVS-COMPUTE | EV score equals the weighted aggregate of dimension scores, normalized to [0, 100] |
| INV-EVS-TIER | Tier classification is consistent with EV score thresholds at all times |
| INV-EVS-UPGRADE | Tier upgrades require documented evidence meeting target tier requirements |
| INV-EVS-DOWNGRADE | Tier downgrades are triggered by expired audit, security advisory, or failed conformance |
