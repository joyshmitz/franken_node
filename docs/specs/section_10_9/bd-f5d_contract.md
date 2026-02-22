# bd-f5d Contract: Public Benchmark Campaign Infrastructure (Node/Bun/franken_node)

## Goal

Deliver reproducible public benchmark infrastructure that compares Node.js, Bun, and franken_node across correctness, performance, resilience, and migration dimensions with machine-verifiable evidence.

## Required Benchmark Workloads (Minimum 10)

1. `http_server_throughput`
2. `module_loading`
3. `cold_start`
4. `json_processing`
5. `file_io`
6. `child_process_spawning`
7. `stream_throughput`
8. `crypto_operations`
9. `url_parsing`
10. `compatibility_shim_overhead`

## Required Dimensions

- `compatibility_correctness`
- `performance`
- `containment_revocation_latency`
- `replay_determinism`
- `adversarial_resilience`
- `migration_speed_failure_rate`

## Quantified Invariants

- `INV-BCI-WORKLOADS`: at least 10 real-world workloads are present.
- `INV-BCI-RUNTIMES`: all runs include Node.js, Bun, and franken_node.
- `INV-BCI-REPRODUCIBLE`: campaign runs in pinned container/runtime environment with deterministic output schema.
- `INV-BCI-METRICS`: every workload emits mean/median/p95/p99 latency and throughput for all runtimes.
- `INV-BCI-TARGETS`: report includes category-defining targets (`>=95%` compatibility, `>=3x` migration velocity, `>=10x` compromise reduction).
- `INV-BCI-RERUN`: single command campaign runner supports baseline-vs-candidate diff output.

## Scoring Formula Version

- `score_formula_version = 2026.02`
- `dimension_score = clamp(0, 100, weighted_metric_sum)`
- weights and normalization constants are published in `fixtures/benchmarks/campaign_manifest.json`.

## Methodology Requirements

- Warmup iterations, measurement iterations, and confidence intervals are documented.
- Outlier policy is documented (trimmed percentile method).
- Harness provenance includes container image digest, runtime versions, and hardware profile.

## Outputs

- Structured JSON campaign results.
- Public comparative Markdown report with tables.
- Diff summary against baseline run.

## Event Codes

- `BCI-001`: campaign execution started
- `BCI-002`: workload suite completed
- `BCI-003`: scoring completed
- `BCI-004`: diff report generated
- `BCI-005`: publication bundle emitted

## Machine-Readable Artifacts

- `fixtures/benchmarks/campaign_manifest.json`
- `fixtures/benchmarks/dataset_catalog.json`
- `fixtures/benchmarks/campaign_results_baseline.json`
- `fixtures/benchmarks/campaign_results_candidate.json`
- `scripts/run_benchmark_campaign.sh`
- `scripts/check_benchmark_infra.py`
