# bd-3gwi: Contribution-Weighted Intelligence Access Policy and Reciprocity Controls

**Section:** 10.19 — Adversarial Trust Commons (9M)
**Status:** Implemented
**Module:** `crates/franken-node/src/federation/atc_reciprocity.rs`

## Purpose

Implements contribution-weighted intelligence access with reciprocity enforcement. Participants' access to threat intelligence feeds is determined by their measured contribution quality and quantity. Free-riders are blocked; exception paths are explicit and auditable.

## Access Tiers

| Tier | Min Quality-Adjusted Ratio | Feeds |
|------|---------------------------|-------|
| Full | >= 0.8 | raw_signals, aggregated, advisories, indicators |
| Standard | >= 0.4 | aggregated, advisories, indicators |
| Limited | >= 0.1 | advisories |
| Blocked | < 0.1 | none |

## Contribution Ratio

```
raw_ratio      = contributions_made / intelligence_consumed   (capped at 1.0)
quality_ratio  = raw_ratio * contribution_quality              (quality in [0,1])
effective      = quality_ratio if use_quality_adjustment else raw_ratio
```

## Free-Rider Controls

- Participants below Limited threshold are Blocked
- Rolling contribution window prevents gaming
- Grace period (default 7 days) for new participants → Standard access
- Approved exception path for research/audit → Standard access with audit trail

## Core Types

| Type | Role |
|------|------|
| `AccessTier` | Blocked < Limited < Standard < Full |
| `ContributionMetrics` | Per-participant contribution data |
| `AccessDecision` | Evaluated access grant/deny with tier and feeds |
| `AccessAuditEntry` | Logged access decision with content hash |
| `ReciprocityMatrix` | Batch snapshot of all participants' tiers |
| `ReciprocityMatrixEntry` | Per-participant matrix entry |
| `ReciprocityConfig` | Configurable tier thresholds, grace period, quality toggle |
| `ReciprocityEngine` | Engine: evaluate access, batch evaluation, audit export |

## Event Codes

| Code | Meaning |
|------|---------|
| ATC-RCP-001 | Access granted |
| ATC-RCP-002 | Access denied |
| ATC-RCP-003 | Tier assigned |
| ATC-RCP-004 | Free-rider enforced |
| ATC-RCP-005 | Exception activated |
| ATC-RCP-006 | Grace period granted |
| ATC-RCP-007 | Contribution updated |
| ATC-RCP-008 | Policy evaluated |
| ATC-RCP-009 | Tier downgraded |
| ATC-RCP-010 | Matrix exported |
| ATC-RCP-ERR-001 | Invalid contribution |
| ATC-RCP-ERR-002 | Policy config error |

## Invariants

| Invariant | Description |
|-----------|-------------|
| INV-ATC-RECIPROCITY-DETERMINISM | Same contribution data produces same tier assignment |
| INV-ATC-TIER-MONOTONE | Higher contribution ratio never produces lower tier |
| INV-ATC-FREERIDER-BOUND | Below-threshold participants cannot access protected feeds |
| INV-ATC-EXCEPTION-AUDITED | Every exception grant produces an audit record |
| INV-ATC-GRACE-BOUNDED | Grace period has finite, configurable duration |
| INV-ATC-ACCESS-LOGGED | Every access decision (grant or deny) is logged |

## Configuration Defaults

| Parameter | Default | Description |
|-----------|---------|-------------|
| full_tier_min_ratio | 0.8 | Min quality-adjusted ratio for Full |
| standard_tier_min_ratio | 0.4 | Min quality-adjusted ratio for Standard |
| limited_tier_min_ratio | 0.1 | Min quality-adjusted ratio for Limited |
| grace_period_seconds | 604,800 | 7 days grace period |
| grace_period_tier | Standard | Access tier during grace period |
| use_quality_adjustment | true | Apply quality to ratio |

## Test Coverage

- 22 Rust inline tests covering all 6 invariants plus serialization, config, batch evaluation
- Python verification gate checks
- Python unit tests

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_19/bd-3gwi_contract.md` |
| Rust module | `crates/franken-node/src/federation/atc_reciprocity.rs` |
| Check script | `scripts/check_atc_reciprocity.py` |
| Unit tests | `tests/test_check_atc_reciprocity.py` |
| Reciprocity matrix | `artifacts/10.19/atc_reciprocity_matrix.json` |
| Evidence | `artifacts/section_10_19/bd-3gwi/verification_evidence.json` |
| Summary | `artifacts/section_10_19/bd-3gwi/verification_summary.md` |
