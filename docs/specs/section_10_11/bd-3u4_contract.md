# bd-3u4 Contract: BOCPD Regime Detector

**Bead:** bd-3u4
**Section:** 10.11 (FrankenSQLite-Inspired Runtime Systems)
**Status:** Active

## Purpose

Implement Bayesian Online Changepoint Detection (BOCPD) per Adams & MacKay
(2007) for detecting regime shifts in workload, incident, and trust-signal
streams.  Enables proactive policy recalibration and early alerting when
operational patterns change.

## Algorithm

BOCPD maintains a posterior distribution over run lengths (time since last
changepoint).  At each timestep:

1. Evaluate the predictive probability of the new observation under each
   possible run length.
2. Compute the growth probability (current regime continues).
3. Compute the changepoint probability (new regime begins).
4. Normalize to obtain the posterior over run lengths.

### Hazard Functions

| Variant  | Formula                     | Use Case                    |
|----------|-----------------------------|-----------------------------|
| Constant | h(r) = 1/lambda             | Default, memoryless         |
| Geometric| h(r) = p * (1-p)^r          | Increasing hazard over time |
| Custom   | h(r) = user-provided fn(r)  | Domain-specific hazard      |

### Observation Models

| Model       | Prior                      | Sufficient Statistics     | Use Case              |
|-------------|----------------------------|---------------------------|-----------------------|
| Gaussian    | Normal-Inverse-Gamma (NIG) | count, mean, var          | Latency, throughput   |
| Poisson     | Gamma(alpha, beta)         | count, sum                | Incident counts       |
| Categorical | Dirichlet(alpha_k)         | count per category        | Error distributions   |

## Data Structures

### `BocpdConfig`

| Field                    | Type   | Default | Description                           |
|--------------------------|--------|---------|---------------------------------------|
| hazard_lambda            | f64    | 200.0   | Constant hazard rate parameter        |
| changepoint_threshold    | f64    | 0.7     | Min posterior prob to signal shift     |
| min_run_length           | usize  | 10      | Min observations before signaling     |
| max_run_length           | usize  | 500     | Truncation for efficiency             |
| max_regime_history       | usize  | 1000    | Bounded regime history log entries    |
| correlation_window_secs  | u64    | 60      | Multi-stream correlation window       |

### `RegimeShift`

Emitted when a changepoint exceeds threshold:

| Field           | Type     | Description                                |
|-----------------|----------|--------------------------------------------|
| stream_name     | String   | Name of the monitored stream               |
| timestamp       | u64      | Detection timestamp (epoch seconds)        |
| confidence      | f64      | Posterior probability of changepoint       |
| run_length      | usize    | Observations since last changepoint        |
| old_regime_mean | f64      | Summary statistic of previous regime       |
| new_regime_mean | f64      | Summary statistic of new regime            |

## Event Codes

| Code     | Severity | Description                                          |
|----------|----------|------------------------------------------------------|
| BCP-001  | INFO     | Observation ingested into BOCPD stream                |
| BCP-002  | WARN     | Changepoint candidate detected (above threshold)      |
| BCP-003  | WARN     | Regime shift confirmed (persisted past min_run_length) |
| BCP-004  | WARN     | Correlated regime shift across multiple streams        |
| BCP-005  | INFO     | False positive suppressed (below min_run_length)       |

## Invariants

- **INV-BCP-POSTERIOR** — Posterior run-length distribution sums to 1.0 (within
  floating-point tolerance of 1e-6) after every update step.
- **INV-BCP-MONOTONIC** — Run-length counts are monotonically increasing within
  a regime.  A new observation either extends the current run or starts a new
  one.
- **INV-BCP-BOUNDED** — Run-length distribution is truncated at
  `max_run_length` to bound memory and computation.
- **INV-BCP-MIN-RUN** — Changepoints are only signaled after `min_run_length`
  observations to suppress transient false positives.

## Error Codes

| Code                        | Description                                |
|-----------------------------|--------------------------------------------|
| ERR_BCP_INVALID_CONFIG      | Configuration parameter out of valid range |
| ERR_BCP_EMPTY_STREAM        | Operation on empty stream                  |
| ERR_BCP_MODEL_MISMATCH      | Observation type doesn't match model       |

## Acceptance Criteria

1. BOCPD core algorithm with constant and geometric hazard functions.
2. Gaussian, Poisson, and Categorical observation models with online updates.
3. Changepoint detection at configurable threshold with min-run-length filter.
4. Multi-stream correlation within configurable time window.
5. Regime history log bounded at configurable max entries.
6. >= 30 unit tests.
7. Golden vectors in `vectors/bocpd_regime_shifts.json`.
8. Verification script passes all checks.

## Dependencies

- bd-2nt (VOI-budgeted monitoring) — downstream consumer
- 10.13 telemetry namespace — event schema

## File Layout

```
docs/specs/section_10_11/bd-3u4_contract.md (this file)
crates/franken-node/src/connector/bocpd.rs
scripts/check_bocpd.py
tests/test_check_bocpd.py
vectors/bocpd_regime_shifts.json
artifacts/section_10_11/bd-3u4/verification_evidence.json
artifacts/section_10_11/bd-3u4/verification_summary.md
```
