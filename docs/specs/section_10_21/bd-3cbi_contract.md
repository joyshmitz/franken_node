# bd-3cbi: BPET Economic Integration and Operator Copilot

**Section:** 10.21 — Behavioral Phenotype Evolution Tracker (9O)
**Track:** BPET Longitudinal Intelligence
**Status:** Implemented

## Purpose

Integrates BPET trajectory-derived compromise risk into the economic trust
layer and provides operator copilot guidance with historical motif matching
and mitigation playbooks. Translates behavioral phenotype signals into
actionable economic language: expected losses, risk-adjusted costs,
intervention ROI, and urgency-prioritized playbooks.

## Behavioral Metrics (6)

| Metric | Risk Interpretation |
|--------|-------------------|
| `maintainer_activity_score` | Low activity = higher risk |
| `commit_velocity` | Low velocity = stagnation risk |
| `issue_response_time_hours` | High latency = neglect risk |
| `dependency_churn_rate` | High churn = instability |
| `security_patch_latency_hours` | High latency = exposure risk |
| `contributor_diversity_index` | Low diversity = bus factor risk |

## Compromise Propensity Scoring

- Trajectory of observations over time
- Trend analysis: activity decline, velocity drop, response degradation, diversity loss
- Formula: `(current_state * 0.4 + trend * 0.6).min(1.0)`
- Output: [0.0, 1.0] bounded propensity score

## Economic Pricing

| Field | Formula |
|-------|---------|
| `risk_adjusted_cost` | propensity x expected_loss |
| `insurance_premium_equivalent` | risk_adjusted_cost x 1.2 (20% loading) |
| `confidence` | propagated from input |

## Intervention ROI

| Recommendation | ROI Ratio |
|---------------|-----------|
| StronglyRecommended | > 5.0 |
| Recommended | > 2.0 |
| Marginal | > 1.0 |
| NotRecommended | <= 1.0 |

Default interventions: `fork_and_maintain`, `sponsor_maintainer`, `sandbox_barriers`, `replace_dependency`.

## Historical Motif Matching

3 default motifs:

1. **Abandoned Critical Package**: activity < 0.2, velocity < 1.0, response > 168h
2. **Sudden Maintainer Turnover**: diversity < 0.3, activity < 0.3
3. **Slow Quality Decay**: patch latency > 48h, churn > 5.0

Match scoring: `matched_indicators / total_indicators`, threshold >= 0.5.

## Mitigation Playbook

| Urgency | Trigger |
|---------|---------|
| Critical | propensity > 0.8 or motif match > 0.8 |
| Urgent | propensity > 0.6 |
| Elevated | propensity > 0.3 |
| Routine | otherwise |

Playbook includes: recommended actions (prioritized), monitoring escalation steps, fallback strategy.

## Core Types

| Type | Role |
|------|------|
| `PhenotypeObservation` | Single behavioral metric snapshot |
| `PhenotypeTrajectory` | Time-ordered observation sequence |
| `CompromisePricing` | Economic risk pricing |
| `InterventionRoi` | ROI analysis for an intervention |
| `InterventionRecommendation` | 4-tier recommendation enum |
| `CompromiseMotif` | Historical compromise pattern |
| `MotifIndicator` | Single indicator within a motif |
| `ThresholdDirection` | Above/Below threshold comparison |
| `MotifMatch` | Result of motif matching |
| `BpetGuidance` | Full operator guidance entry |
| `BpetMitigationPlaybook` | Urgency-tagged playbook |
| `PlaybookUrgency` | Routine/Elevated/Urgent/Critical |
| `PlaybookAction` | Individual playbook action |
| `BpetAuditRecord` | Per-interaction audit record |
| `BpetEconomicEngine` | Main engine for guidance generation |

## Event Codes

| Code | Description |
|------|-------------|
| `BPET-ECON-001` | Risk priced for a package trajectory |
| `BPET-ECON-002` | Intervention ROI computed |
| `BPET-ECON-003` | Historical motif matched |
| `BPET-ECON-004` | Mitigation playbook generated |
| `BPET-ECON-005` | Operator guidance served |
| `BPET-ECON-006` | Compromise propensity threshold breached |
| `BPET-ECON-007` | Trajectory assessment completed |
| `BPET-ECON-008` | Intervention recommended |
| `BPET-ECON-009` | Economic report emitted |
| `BPET-ECON-010` | Calibration warning issued |

## Acceptance Criteria

1. Economic models price trajectory-derived compromise propensity with bounded [0,1] output.
2. Risk-adjusted cost = propensity x expected_loss; insurance premium includes loading factor.
3. Intervention ROI computed with payback period; 4-tier recommendation classification.
4. Historical motif matching against library with >= 3 default patterns.
5. Operator guidance includes motif matches, interventions, and urgency-tagged playbook.
6. Audit logging for every guidance interaction with trace correlation IDs.
7. JSONL export for post-hoc audit replay.
8. All types implement Serialize/Deserialize for JSON round-trip.

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_21/bd-3cbi_contract.md` |
| Rust module | `crates/franken-node/src/security/bpet/economic_integration.rs` |
| Module wiring | `crates/franken-node/src/security/bpet/mod.rs` |
| Check script | `scripts/check_bpet_economic.py` |
| Unit tests | `tests/test_check_bpet_economic.py` |
| Guidance report | `artifacts/10.21/bpet_economic_guidance_report.csv` |
| Evidence | `artifacts/section_10_21/bd-3cbi/verification_evidence.json` |
| Summary | `artifacts/section_10_21/bd-3cbi/verification_summary.md` |

## Dependencies

- None (standalone economic integration layer).
- Depended on by: bd-zm5b (section gate), bd-37i (plan tracker).
