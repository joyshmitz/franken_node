# bd-18ie: Compatibility Correctness Metrics by API/Risk Band — Spec Contract

**Section:** 14 — Benchmark + Standardization
**Bead:** bd-18ie
**Status:** CLOSED

## Purpose

Instrument compatibility correctness metric family segmented by API family and
risk band for release-gated quality enforcement.

## Acceptance Criteria

1. Five API families: Core, Extension, Management, Telemetry, Migration.
2. Four risk bands: Critical (99.9%), High (99.5%), Medium (99%), Low (95%).
3. Correctness metrics segmented by (API family, risk band) pair (INV-CCM-SEGMENTED).
4. Same inputs produce same report (INV-CCM-DETERMINISTIC).
5. APIs below correctness threshold flagged (INV-CCM-GATED).
6. Regressions detected when correctness drops (INV-CCM-REGRESSION).
7. Metric version embedded in every report (INV-CCM-VERSIONED).
8. Every submission produces audit record (INV-CCM-AUDITABLE).
9. At least 12 event codes (CCM-001 through CCM-ERR-002).
10. At least 24 Rust unit tests.

## Invariants

| ID | Description |
|---|---|
| INV-CCM-SEGMENTED | Metrics segmented by API family and risk band |
| INV-CCM-DETERMINISTIC | Same inputs produce same metric report |
| INV-CCM-GATED | APIs below correctness threshold flagged |
| INV-CCM-REGRESSION | Regressions detected when correctness drops |
| INV-CCM-VERSIONED | Standard version embedded in every report |
| INV-CCM-AUDITABLE | Every metric submission produces audit record |

## Event Codes

| Code | Description |
|---|---|
| CCM-001 | Metric submitted |
| CCM-002 | Correctness rate computed |
| CCM-003 | Regression detected |
| CCM-004 | Threshold checked |
| CCM-005 | Report generated |
| CCM-006 | API family registered |
| CCM-007 | Risk band assigned |
| CCM-008 | Aggregate computed |
| CCM-009 | Confidence computed |
| CCM-010 | Version embedded |
| CCM-ERR-001 | Below threshold |
| CCM-ERR-002 | Invalid metric |

## Implementation

| Artifact | Path |
|---|---|
| Rust module | `crates/franken-node/src/tools/compatibility_correctness_metrics.rs` |
| Module wiring | `crates/franken-node/src/tools/mod.rs` |
| Verification script | `scripts/check_compatibility_correctness_metrics.py` |
| Unit tests | `tests/test_check_compatibility_correctness_metrics.py` |
