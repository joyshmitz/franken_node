# bd-wzjl: Security and Trust Co-Metrics

**Section:** 14 — Benchmark + Standardization
**Status:** Implemented
**Module:** `crates/franken-node/src/tools/security_trust_metrics.rs`

## Purpose

Expands the benchmark suite beyond speed-only metrics to include quantified, machine-verifiable security posture and operational trust dimensions. Each co-metric produces a score in [0, 1] with confidence intervals, enabling release-gating on security/trust properties alongside performance.

## Security Co-Metric Categories (5)

| Category | ID | Description |
|----------|----|-------------|
| Sandbox Enforcement | SECM-SANDBOX | Escape attempts blocked percentage |
| Revocation Propagation | SECM-REVOCATION | Latency and completeness |
| Policy Evaluation | SECM-POLICY | Throughput and accuracy |
| Attestation Verification | SECM-ATTESTATION | Verification rate and freshness |
| Quarantine Activation | SECM-QUARANTINE | Activation speed and containment scope |

## Trust Co-Metric Categories (5)

| Category | ID | Description |
|----------|----|-------------|
| Trust Cards | TRUSTM-CARD | Issuance completeness and validity |
| VEF Proofs | TRUSTM-VEF | Proof coverage and verification success |
| Epoch Barriers | TRUSTM-EPOCH | Barrier integrity and transition latency |
| Evidence Ledger | TRUSTM-EVIDENCE | Completeness and durability |
| Reputation Signals | TRUSTM-REPUTATION | Signal accuracy and convergence |

## Gate Behavior

- Default pass threshold: 0.7 for all metrics
- Default warning threshold: 0.8
- When `require_all_categories` is true (default), all 10 categories must be measured
- Any metric below pass threshold blocks release progression
- Scoring formula version embedded in every report for reproducibility

## Invariants

| Invariant | Description |
|-----------|-------------|
| INV-SECM-QUANTIFIED | Every metric has a numeric score in [0, 1] |
| INV-SECM-DETERMINISTIC | Same inputs produce same metric scores |
| INV-SECM-THRESHOLDED | Every metric has configurable pass/fail thresholds |
| INV-SECM-CONFIDENCE | Every metric includes confidence intervals |
| INV-SECM-VERSIONED | Scoring formulas are versioned for reproducibility |
| INV-SECM-GATED | Metrics below threshold block release progression |

## Event Codes

| Code | Meaning |
|------|---------|
| SECM-001 | Metric computation started |
| SECM-002 | Security metric completed |
| SECM-003 | Trust metric completed |
| SECM-004 | Threshold check passed |
| SECM-005 | Threshold check failed |
| SECM-006 | Report generated |
| SECM-007 | Regression detected |
| SECM-008 | Formula version recorded |
| SECM-009 | Confidence interval computed |
| SECM-010 | Gate evaluation completed |
| SECM-ERR-001 | Metric computation failed |
| SECM-ERR-002 | Invalid configuration |

## Test Coverage

- 18 Rust inline tests covering all 6 invariants
- Python verification gate checks
- Python unit tests
