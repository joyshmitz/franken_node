# bd-3i6c — FrankenSQLite-Inspired Conformance Suite

**Section:** 10.14 — Remote Capabilities & Protocol Testing
**Status:** Implemented

## Overview

Capstone verification artifact for the 9J track. Provides normative test
fixtures verifying four critical runtime properties: ledger determinism,
idempotency, epoch validity, and marker/MMR proof correctness. Each test
has a stable conformance ID (FSQL-{domain}-NNN) for tracking and regression
detection. Release builds require all conformance tests passing.

## Conformance Domains

| Domain | Prefix | Min Fixtures | Actual | Description |
|--------|--------|-------------|--------|-------------|
| Determinism | FSQL-DET | 10 | 11 | Identical input produces identical output |
| Idempotency | FSQL-IDP | 8 | 10 | Repeated operations produce same result |
| EpochValidity | FSQL-EPO | 12 | 13 | All epoch invariants hold |
| ProofCorrectness | FSQL-PRF | 10 | 11 | Proofs verify correctly |

**Total: 45 fixtures (min 40)**

## Invariants

| ID | Statement |
|----|-----------|
| INV-CONF-DETERMINISTIC | Operations produce identical output for identical input |
| INV-CONF-IDEMPOTENT | Repeated operations produce same result as single |
| INV-CONF-EPOCH-VALID | All epoch-related invariants hold |
| INV-CONF-PROOF-CORRECT | All proof operations are correct |
| INV-CONF-STABLE-IDS | Conformance IDs are permanent and never reused |
| INV-CONF-RELEASE-GATE | Release builds require all conformance tests passing |

## Event Codes (6)

CONFORMANCE_SUITE_START, CONFORMANCE_TEST_PASS, CONFORMANCE_TEST_FAIL,
CONFORMANCE_SUITE_COMPLETE, CONFORMANCE_FIXTURE_LOADED, CONFORMANCE_REPORT_EXPORTED

## Error Codes (8)

ERR_CONF_DETERMINISM_MISMATCH, ERR_CONF_IDEMPOTENCY_VIOLATION,
ERR_CONF_EPOCH_INVARIANT_BROKEN, ERR_CONF_PROOF_INVALID,
ERR_CONF_DUPLICATE_ID, ERR_CONF_FIXTURE_PARSE,
ERR_CONF_RELEASE_BLOCKED, ERR_CONF_MISSING_DOMAIN

## Operations

| Operation | Description |
|-----------|-------------|
| register_fixture | Register a fixture with unique conformance ID |
| register_builtin_fixtures | Load all 45 built-in fixtures |
| run_all | Execute all fixtures with test function |
| check_release_gate | Verify no failures → eligible for release |
| domain_coverage | Count fixtures per domain |
| verify_domain_coverage | Ensure all four domains represented |
| export_report_json | Export conformance report as JSON |
| export_audit_log_jsonl | Export audit log as JSONL |

## Key Types

- `ConformanceDomain` — enum: Determinism, Idempotency, EpochValidity, ProofCorrectness
- `ConformanceId` — stable ID (e.g., FSQL-DET-001)
- `ConformanceTestResult` — Pass | Fail
- `ConformanceTestRecord` — per-test result with timing
- `ConformanceReport` — suite execution report with release eligibility
- `ConformanceFixture` — input/expected pair with conformance ID
- `ConformanceSuiteRunner` — the suite runner

## Schema Version

`cs-v1.0`

## Acceptance Criteria

1. >= 40 total conformance fixtures across 4 domains
2. >= 10 determinism, >= 8 idempotency, >= 12 epoch, >= 10 proof fixtures
3. All conformance IDs are unique and stable
4. Release gate blocks release on any failure
5. Conformance report includes per-test results
6. JSONL audit log with suite lifecycle events
7. 25+ inline Rust tests
