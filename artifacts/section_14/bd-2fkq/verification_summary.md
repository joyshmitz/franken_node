# bd-2fkq: Migration Speed and Failure-Rate Metrics — Verification Summary

**Section:** 14 | **Bead:** bd-2fkq | **Date:** 2026-02-20

## Gate Result: PASS (20/20)

All checks passed:
- Source exists and module wired in mod.rs
- 5 migration phases (Assessment, DependencyResolution, CodeAdaptation, TestValidation, Deployment)
- 5 failure types (DependencyConflict, ApiIncompatibility, RuntimeError, TestRegression, ConfigurationError)
- 5 required structs (MigrationRecord, PhaseStats, FailureStats, MigrationSpeedReport, MigrationSpeedFailureMetrics)
- Per-phase duration tracking with PhaseDuration
- Failure rate with MAX_FAILURE_RATE threshold (5%)
- Speed computation with avg + p90 durations
- Threshold gating with exceeds_threshold flag
- SHA-256 content hashing
- 12/12 event codes (MSF-001..MSF-010, MSF-ERR-001, MSF-ERR-002)
- 6/6 invariants (INV-MSF-PHASED/CATEGORIZED/DETERMINISTIC/GATED/VERSIONED/AUDITABLE)
- JSONL audit export with MsfAuditRecord
- Metric version msf-v1.0
- Spec contract aligned
- 24 Rust in-module tests

## Test Results
- **Gate script:** 20/20 PASS
- **Python tests:** 28/28 PASS
- **Rust tests:** 24 in-module tests
