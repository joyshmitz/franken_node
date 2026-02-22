# Benchmark Campaign Methodology (bd-f5d)

## Statistical Rigor

- Warm-up policy: 5 warm-up iterations per workload/runtime pair.
- Measured iterations: 30 per workload/runtime pair.
- Confidence interval: 95% CI using bootstrap resampling (10k resamples).
- Outlier handling: winsorize at p1/p99, report original p95/p99 separately.

## Reproducibility Controls

- Hermetic container image with pinned digest.
- Pinned runtime versions for Node.js, Bun, and franken_node.
- Fixed hardware profile (`c7i.4xlarge-equivalent`) for campaign baselines.
- Full provenance recorded in JSON output.

## Publication Rules

- All benchmark datasets are public and hash-addressable.
- Public report includes workload-level tables and target attainment highlights.
- Every campaign run emits a baseline diff summary.

## Release Cadence

- Full campaign: release candidate and GA releases.
- Smoke subset: every release CI run.
