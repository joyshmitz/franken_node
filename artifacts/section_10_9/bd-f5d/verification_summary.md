# bd-f5d Verification Summary

- Bead: `bd-f5d`
- Section: `10.9`
- Capability: `Public Node/Bun/franken_node benchmark campaign infrastructure`
- Verdict: `PASS`

## Scope Delivered

- Spec/contract: `docs/specs/section_10_9/bd-f5d_contract.md`
- Methodology doc: `docs/policy/benchmark_campaign_methodology.md`
- Benchmark fixtures: `fixtures/benchmarks/*` (manifest, dataset catalog, baseline/candidate results, chart spec)
- Campaign runner: `scripts/run_benchmark_campaign.sh`
- Verifier: `scripts/check_benchmark_infra.py`
- Unit tests: `tests/test_check_benchmark_infra.py`

## Acceptance Results

- Campaign compares Node/Bun/franken_node across 10 required workloads.
- Harness metadata is hermetic and pinned (container digest + runtime versions).
- Structured JSON contains per-workload and per-runtime mean/median/p95/p99 + throughput metrics.
- Comparative public report generator emits Markdown table + target highlights.
- Category-defining targets are highlighted and pass (`>=95%` compatibility, `>=3x` migration velocity, `>=10x` compromise reduction).
- Single-command rerun script generates campaign output and diff against baseline.
- Methodology documents warmup, iterations, outlier policy, and confidence interval.

## Verification Commands

```bash
python3 scripts/check_benchmark_infra.py --self-test --json
python3 scripts/check_benchmark_infra.py --json
python3 -m unittest tests/test_check_benchmark_infra.py
scripts/run_benchmark_campaign.sh --baseline fixtures/benchmarks/campaign_results_baseline.json --candidate fixtures/benchmarks/campaign_results_candidate.json --output artifacts/section_10_9/bd-f5d/campaign_run.json
```
