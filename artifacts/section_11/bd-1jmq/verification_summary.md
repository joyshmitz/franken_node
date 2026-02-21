# bd-1jmq: EV Score and Tier — Verification Summary

## Result: PASS

| Metric | Value |
|--------|-------|
| Verification checks | 20/20 |
| Python unit tests | 59/59 |
| Verdict | **PASS** |
| Agent | CrimsonCrane |

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_11/bd-1jmq_contract.md` |
| Policy document | `docs/policy/ev_score_and_tier.md` |
| Verification script | `scripts/check_ev_score.py` |
| Python tests | `tests/test_check_ev_score.py` |
| Evidence JSON | `artifacts/section_11/bd-1jmq/verification_evidence.json` |
| This summary | `artifacts/section_11/bd-1jmq/verification_summary.md` |

## Coverage

- Spec contract defines EV score formula, 5 verification dimensions, 5 tiers (T0-T4)
- Policy document covers weights, thresholds, upgrade path, downgrade triggers, governance
- 4 event codes: EVS-001 (score computed), EVS-002 (tier assigned), EVS-003 (tier upgraded), EVS-004 (downgrade warning)
- 4 invariants: INV-EVS-COMPUTE, INV-EVS-TIER, INV-EVS-UPGRADE, INV-EVS-DOWNGRADE
- Tier thresholds: T0 (0-19), T1 (20-39), T2 (40-59), T3 (60-79), T4 (80-100)
- Dimension weights: code_review (0.20), test_coverage (0.20), security_audit (0.25), supply_chain (0.15), conformance (0.20)
- Upgrade path: per-transition requirements documented
- Downgrade triggers: expired audit, security advisory, failed conformance, supply chain failure
- Governance: weight adjustment process, appeal process, audit trail
- Trust card integration: tier badge, numeric score, dimension breakdown, trend indicator

## Verification Checks (20)

| # | Check | Result |
|---|-------|--------|
| 1 | Spec contract file exists | PASS |
| 2 | Policy document exists | PASS |
| 3 | Spec keyword: EV score | PASS |
| 4 | Spec keyword: tier | PASS |
| 5 | Spec tiers T0-T4 defined | PASS |
| 6 | Spec keyword: verification | PASS |
| 7 | Spec keyword: weighted | PASS |
| 8 | Spec event codes EVS-001 through EVS-004 | PASS |
| 9 | Spec invariants INV-EVS-* | PASS |
| 10 | Spec tier thresholds (5 ranges) | PASS |
| 11 | Spec upgrade path section | PASS |
| 12 | Spec downgrade triggers section | PASS |
| 13 | Policy dimensions (5) | PASS |
| 14 | Policy weights (0.20, 0.25, 0.15) | PASS |
| 15 | Policy governance section | PASS |
| 16 | Policy appeal process | PASS |
| 17 | Policy tier thresholds | PASS |
| 18 | Policy event codes | PASS |
| 19 | Policy invariants | PASS |
| 20 | Policy downgrade triggers | PASS |
