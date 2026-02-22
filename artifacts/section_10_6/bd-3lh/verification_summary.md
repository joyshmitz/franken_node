# bd-3lh Verification Summary

## Bead: bd-3lh | Section: 10.6
## Title: Cold-Start and P99 Latency Gates for Core Workflows

## Verdict: PASS (17/17 checks)

## Artifacts Delivered

| Artifact | Path | Status |
|----------|------|--------|
| Specification | `docs/specs/section_10_6/bd-3lh_contract.md` | Delivered |
| Budget config | `perf/budgets.toml` | Delivered |
| Verification script | `scripts/check_latency_gates.py` | Delivered |
| Unit tests | `tests/test_check_latency_gates.py` | Delivered |
| Evidence JSON | `artifacts/section_10_6/bd-3lh/verification_evidence.json` | Delivered |
| This summary | `artifacts/section_10_6/bd-3lh/verification_summary.md` | Delivered |

## Implementation Details

### Budget Configuration (`perf/budgets.toml`)
- **3 deployment profiles**: dev_local, ci_dev, enterprise
- **5 core workflows**: migration_scan, compatibility_check, policy_evaluation, trust_card_lookup, incident_replay
- **Per-workflow overrides** for migration_scan and incident_replay (heavier workloads)
- Enterprise budgets are provably stricter than dev_local (verified)
- Minimum 30 iterations, 5 warmup iterations for statistical validity

### Budget Values

| Profile | Cold-Start | P99 Latency |
|---------|-----------|-------------|
| dev_local | 500ms | 50ms |
| ci_dev | 200ms | 20ms |
| enterprise | 100ms | 10ms |

### Verification Script (`check_latency_gates.py`)
- 17 checks covering spec, budget config, event codes, invariants, statistics
- Self-test mode validates script integrity
- Profile-aware (--profile flag)
- Budget resolution with per-workflow overrides verified
- Percentile computation validated against known data

### Python Tests (`test_check_latency_gates.py`)
- 24 tests in 9 test classes
- Covers self-test, JSON output, spec checks, keywords, event codes, invariants, budget config, statistics, overall verdict

## Key Design Decisions

1. **Three-tier profiles**: dev_local/ci_dev/enterprise reflect actual deployment contexts.
2. **Per-workflow overrides**: migration_scan and incident_replay get looser budgets due to inherent I/O and compute intensity.
3. **80% early warning**: Alerts before hard failure at 100% of budget.
4. **Version-controlled budgets**: TOML in `perf/budgets.toml` with changelog.
5. **Flamegraph evidence**: Spec requires SVG generation at 80%+ threshold.
