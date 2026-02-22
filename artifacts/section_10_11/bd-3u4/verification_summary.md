# bd-3u4 Verification Summary

## Bead: bd-3u4 | Section: 10.11
## Title: BOCPD Regime Detector

## Verdict: PASS (70/70 checks)

## Artifacts Delivered

| Artifact | Path | Status |
|----------|------|--------|
| Specification | `docs/specs/section_10_11/bd-3u4_contract.md` | Delivered |
| Rust module | `crates/franken-node/src/connector/bocpd.rs` | Delivered |
| Module registration | `crates/franken-node/src/connector/mod.rs` | Delivered |
| Verification script | `scripts/check_bocpd.py` | Delivered |
| Unit tests | `tests/test_check_bocpd.py` | Delivered |
| Golden vectors | `vectors/bocpd_regime_shifts.json` | Delivered |
| Evidence JSON | `artifacts/section_10_11/bd-3u4/verification_evidence.json` | Delivered |
| This summary | `artifacts/section_10_11/bd-3u4/verification_summary.md` | Delivered |

## Algorithm

Adams & MacKay (2007) Bayesian Online Changepoint Detection. Maintains a posterior distribution over run lengths (time since last changepoint). At each timestep evaluates predictive probability, computes growth and changepoint mass, normalizes the posterior, and checks for regime shifts.

## Implementation Details

### Core Types

| Type | Description |
|------|-------------|
| `BocpdConfig` | Configuration with hazard_lambda, changepoint_threshold, min/max_run_length, etc. |
| `BocpdDetector` | Single-stream BOCPD detector with online update |
| `RegimeShift` | Emitted regime shift record with stream_name, timestamp, confidence, run_length, old/new regime means |
| `MultiStreamCorrelator` | Cross-stream correlation within configurable time window |
| `BocpdEvent` | Event log entry with code and detail |
| `BocpdError` | Error enum: InvalidConfig, EmptyStream, ModelMismatch |
| `HazardFunction` | Enum: Constant (1/lambda), Geometric (p) |
| `ObservationModel` | Enum: Gaussian, Poisson, Categorical |
| `GaussianModel` | Normal-Inverse-Gamma conjugate prior (mu0, kappa0, alpha0, beta0) |
| `PoissonModel` | Gamma conjugate prior (alpha0, beta0) |
| `CategoricalModel` | Dirichlet conjugate prior (k categories, alpha0) |

### Mathematical Functions

- `ln_gamma` — Lanczos approximation (g=7, n=9) with reflection formula
- `student_t_pdf` — Student-t distribution PDF for Gaussian predictive
- `neg_binomial_pmf` — Negative binomial PMF for Poisson predictive

### Methods (14 total)

- `BocpdConfig::validate()` — Config validation
- `HazardFunction::evaluate()` — Hazard rate at run length r
- `GaussianModel/PoissonModel/CategoricalModel::predictive_prob()` — Conjugate predictive probability
- `BocpdDetector::new()` — Create detector with config, hazard, model
- `BocpdDetector::observe()` — Process observation, return Optional regime shift
- `BocpdDetector::map_run_length()` — MAP run length estimate
- `BocpdDetector::changepoint_probability()` — P(r_t = 0)
- `BocpdDetector::regime_history()` — Bounded regime shift log
- `BocpdDetector::observation_count()` — Total observations processed
- `BocpdDetector::events()` — Event log
- `BocpdDetector::posterior_sum()` — Verify INV-BCP-POSTERIOR
- `BocpdDetector::stream_name()` — Stream identifier
- `MultiStreamCorrelator::record_shift()` — Record and correlate shifts
- `MultiStreamCorrelator::recent_count()` — Count shifts in window

### Invariants Enforced

- **INV-BCP-POSTERIOR**: Posterior sums to 1.0 (within 1e-6) after every update
- **INV-BCP-MONOTONIC**: Run-length monotonically increases within a regime
- **INV-BCP-BOUNDED**: Distribution truncated at max_run_length
- **INV-BCP-MIN-RUN**: Changepoints only signaled after min_run_length observations

### Rust Unit Tests (34 tests)

Coverage: config validation (valid, invalid lambda/threshold/max_run_length), detector creation (Gaussian/Poisson/Categorical), single observations, posterior normalization (initial, after 50 obs), run-length monotonicity, stable stream no-changepoint, Gaussian changepoint detection, min_run_length suppression, bounded truncation, constant/geometric hazard, predictive probabilities (Gaussian/Poisson/Categorical, sum-to-one), sufficient statistics updates, regime history bounding, multi-stream correlation (none, detected, outside window), error display, ln_gamma sanity, events recorded.

### Compilation

Binary target compiles via `rch exec -- cargo check --bin frankenengine-node` (exit 0).
