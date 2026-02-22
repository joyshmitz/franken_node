# bd-ufk5: VEF Performance Budget Gates — Verification Summary

**Section:** 10.18 — Verifiable Execution Fabric
**Verdict:** PASS
**Date:** 2026-02-21

## What Was Delivered

Performance budget gates for VEF overhead in control-plane and extension-host
hot paths. The implementation enforces per-operation, per-mode latency budgets
at p95 and p99 percentiles with noise tolerance and regression detection.

## Key Metrics

| Metric | Value |
|--------|-------|
| Rust unit tests | 30 |
| Python verification checks | 62/62 |
| Python unit tests | 16/16 |
| Self-test checks | 12/12 |
| VEF operations covered | 7 |
| Budget modes | 3 |
| Budget pairs defined | 21 |
| Event codes | 6 |
| Invariants verified | 6 |

## Acceptance Criteria Outcomes

1. Budget thresholds defined for all 7 ops x 3 modes = 21 pairs — **PASS**
2. Normal tightest, quarantine most relaxed — **PASS**
3. p99 >= p95 for every pair — **PASS**
4. Gate passes when within budget — **PASS**
5. Gate fails on budget exceed — **PASS**
6. Unstable measurements skipped (not failed) — **PASS**
7. Insufficient samples skipped — **PASS**
8. Baseline serializable and supports regression — **PASS**
9. Regression detection works — **PASS**
10. Deterministic evaluation — **PASS**

## Files Delivered

| File | Purpose |
|------|---------|
| `crates/franken-node/src/tools/vef_perf_budget_gate.rs` | Rust implementation (30 unit tests) |
| `crates/franken-node/src/tools/mod.rs` | Module wiring |
| `docs/specs/section_10_18/bd-ufk5_contract.md` | Specification contract |
| `scripts/check_vef_perf_budget_gate.py` | Verification script |
| `tests/test_check_vef_perf_budget_gate.py` | Python unit tests |
| `artifacts/section_10_18/bd-ufk5/verification_evidence.json` | CI evidence |
| `artifacts/section_10_18/bd-ufk5/verification_summary.md` | This file |

## Architecture Notes

- `VefPerfBudgetGate` engine evaluates measurements against `VefPerfBudgetConfig`.
- `VefPerfBudgetConfig` defaults cover all 7 operations with per-mode budgets.
- `BaselineSnapshot` supports commit-tagged regression tracking.
- `RegressionReport` computes delta percentages for p95/p99.
- All types implement `Serialize`/`Deserialize` for JSON round-trip.
- Audit events use structured codes `VEF-PERF-001` through `VEF-PERF-005`.
