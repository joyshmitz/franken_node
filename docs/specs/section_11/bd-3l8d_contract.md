# bd-3l8d Contract: Benchmark And Correctness Artifacts

## Purpose

Define a mandatory, machine-verifiable contract field named
`change_summary.benchmark_and_correctness_artifacts` for subsystem proposals.

This field ensures every major subsystem proposal includes both quantitative
benchmark evidence and correctness evidence before merge.

## Contract Field

Path:
- `change_summary.benchmark_and_correctness_artifacts`

Required sub-fields:
1. `benchmark_metrics` (non-empty list)
2. `correctness_suites` (non-empty list)

### benchmark_metrics

Each entry MUST contain:
- `metric_name` (non-empty string)
- `unit` (non-empty string)
- `measured_value` (number)
- `baseline_value` (number)
- `delta` (number, must equal `measured_value - baseline_value`)
- `within_acceptable_bounds` (boolean)
- `artifact_path` (non-empty string path to existing file)

Additional rules:
- At least one benchmark metric is required.
- `artifact_path` must start with `artifacts/section_` and resolve to an
  existing file.

### correctness_suites

Each entry MUST contain:
- `suite_name` (non-empty string)
- `pass_count` (integer >= 0)
- `fail_count` (integer >= 0)
- `coverage_percent` (number in range `0..100`)
- `raw_output_artifact` (non-empty string path to existing file)

Additional rules:
- At least one correctness suite is required.
- `pass_count + fail_count` must be greater than zero.
- `raw_output_artifact` must start with `artifacts/section_` and resolve to an
  existing file.

## Enforcement

Validator:
- `scripts/check_benchmark_correctness_artifacts.py`

Unit tests:
- `tests/test_check_benchmark_correctness_artifacts.py`

CI gate:
- `.github/workflows/benchmark-correctness-artifacts-gate.yml`

## Event Codes

- `CONTRACT_BENCH_CORRECT_VALIDATED` (info)
- `CONTRACT_BENCH_CORRECT_MISSING` (error)
- `CONTRACT_BENCH_CORRECT_INCOMPLETE` (error)

## Acceptance Mapping

- Benchmark + correctness sections are mandatory on subsystem proposals.
- Benchmark entries require metric, unit, measured/baseline/delta, threshold
  flag, and existing artifact path.
- Correctness entries require suite counts, coverage, and existing raw output
  artifact path.
- CI gate rejects contracts with zero benchmark metrics or zero correctness
  suites.
