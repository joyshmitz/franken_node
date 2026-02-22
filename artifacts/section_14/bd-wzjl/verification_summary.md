# bd-wzjl: Security and Trust Co-Metrics — Verification Summary

**Section:** 14 (Benchmark + Standardization)
**Bead:** bd-wzjl
**Verdict:** PASS
**Date:** 2026-02-21

## Implementation

Implemented security and trust co-metrics in `crates/franken-node/src/tools/security_trust_metrics.rs`.

### Security Co-Metric Categories (5)

| Category | ID | Description |
|---|---|---|
| Sandbox Enforcement | SECM-SANDBOX | Escape attempts blocked percentage |
| Revocation Propagation | SECM-REVOCATION | Latency and completeness |
| Policy Evaluation | SECM-POLICY | Throughput and accuracy |
| Attestation Verification | SECM-ATTESTATION | Verification rate and freshness |
| Quarantine Activation | SECM-QUARANTINE | Activation speed and containment scope |

### Trust Co-Metric Categories (5)

| Category | ID | Description |
|---|---|---|
| Trust Cards | TRUSTM-CARD | Issuance completeness and validity |
| VEF Proofs | TRUSTM-VEF | Proof coverage and verification success |
| Epoch Barriers | TRUSTM-EPOCH | Barrier integrity and transition latency |
| Evidence Ledger | TRUSTM-EVIDENCE | Completeness and durability |
| Reputation Signals | TRUSTM-REPUTATION | Signal accuracy and convergence |

### Invariants Verified

| Invariant | Description |
|---|---|
| INV-SECM-QUANTIFIED | Every metric has numeric score in [0, 1] |
| INV-SECM-DETERMINISTIC | Same inputs produce same scores |
| INV-SECM-THRESHOLDED | Configurable pass/fail thresholds |
| INV-SECM-CONFIDENCE | Confidence intervals on all measurements |
| INV-SECM-VERSIONED | Scoring formula versioned for reproducibility |
| INV-SECM-GATED | Below-threshold metrics block release |

## Test Coverage

| Suite | Count | Status |
|---|---|---|
| Rust unit tests | 18 | Module compiles clean |
| Python verification gate checks | 73 | All pass |
| Python unit tests | 25 | All pass |

## Artifacts

| Artifact | Path |
|---|---|
| Implementation | `crates/franken-node/src/tools/security_trust_metrics.rs` |
| Spec contract | `docs/specs/section_14/bd-wzjl_contract.md` |
| Verification script | `scripts/check_security_trust_metrics.py` |
| Python tests | `tests/test_check_security_trust_metrics.py` |
| Evidence JSON | `artifacts/section_14/bd-wzjl/verification_evidence.json` |

## Dependencies

- **Upstream:** bd-3h1g (benchmark specs)
- **Downstream:** bd-2l4i (section gate), bd-yz3t (verifier toolkit), bd-2ke (plan tracker)
