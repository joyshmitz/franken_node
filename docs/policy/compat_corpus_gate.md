# Compatibility Corpus Gate Policy

**Bead:** bd-28sz
**Section:** 13 (Program Success Criteria Instrumentation)
**Effective:** 2026-02-20

## Purpose

This policy establishes the compatibility corpus gate as a mandatory release
checkpoint. No release of franken_node may proceed unless the compatibility test
corpus demonstrates >= 95% aggregate pass rate and all per-module floors are met.

## Scope

This policy applies to every release candidate produced by the franken_node build
pipeline, including:

- Major releases
- Minor releases
- Patch releases
- Release candidates and beta releases

Pre-release development builds are exempt from the gate but SHOULD run the corpus
for early signal.

## Gate Tiers

The corpus pass rate determines the gate tier and release decision:

| Tier | Pass Rate Range | Release Decision | Required Action                      |
|------|-----------------|------------------|--------------------------------------|
| `G0` | < 80%          | Blocked          | Critical: triage failing modules immediately |
| `G1` | 80-89%         | Blocked          | Needs work: fix failing tests before next attempt |
| `G2` | 90-94%         | Blocked          | Near threshold: targeted fixes to reach 95% |
| `G3` | 95-99%         | Allowed          | Passing: release may proceed         |
| `G4` | 100%           | Allowed          | All tests passing: ideal state       |

Only `G3` and `G4` permit a release to proceed.

## Invariants

### INV-CCG-OVERALL

The aggregate pass rate across all modules must be >= 95%. This is a hard gate
with no override mechanism. The threshold was chosen to balance comprehensive
compatibility coverage against the practical reality that some edge-case tests
may remain pending.

### INV-CCG-FAMILY-FLOOR

No individual module (API family) may fall below 80% pass rate. Even if the
aggregate exceeds 95%, a single module at 79% blocks the release. This prevents
hiding severe per-module incompatibility behind a high aggregate score.

### INV-CCG-RATCHET

The aggregate pass rate must never decrease between consecutive corpus runs. This
strict ratchet (0% regression tolerance) ensures that fixes are permanent and that
new code does not regress existing compatibility. When a regression is detected,
event code CCG-004 is emitted and the release is blocked.

### INV-CCG-REPRODUCIBILITY

Every gate decision, whether pass or fail, must be accompanied by the full corpus
run evidence and must be reproducible. Evidence includes:

- Run identifier and timestamp
- Aggregate and per-module pass rates
- Module-level test counts (passed, failed, skipped, errored)
- Wall-clock duration
- Gate tier classification
- Corpus version and franken_node version for reproducibility

This ensures auditability, traceability, and independent verification of all
release decisions.

## Event Codes

| Code    | Severity | Description                                    |
|---------|----------|------------------------------------------------|
| CCG-001 | Info     | Corpus run completed                           |
| CCG-002 | Info     | Gate threshold met (release allowed)           |
| CCG-003 | Error    | Gate threshold not met (release blocked)       |
| CCG-004 | Error    | Regression detected (pass rate decreased)      |

All events are emitted as structured log entries with stable codes suitable for
automated monitoring and alerting.

## Pass Rate Calculation

```
aggregate_rate = (passed_tests / total_tests) * 100
module_rate    = (module_passed / module_total) * 100
```

- Skipped tests count in the denominator (reduce the pass rate)
- Errored tests (infrastructure failures) count as failures
- Empty modules (0 total tests) are excluded from per-module evaluation

## Thresholds

| Threshold              | Value       | Enforcement                              |
|------------------------|-------------|------------------------------------------|
| Aggregate pass rate    | >= 95%      | Hard gate, no override                   |
| Per-module floor       | >= 80%      | Hard gate per module                     |
| Regression tolerance   | 0%          | Strict ratchet, no regression allowed    |
| Max corpus run time    | <= 30 min   | Soft limit, emits warning if exceeded    |

## Gate Decision Flow

1. Execute the full compatibility test corpus
2. Record all test results with module-level granularity
3. Compute `aggregate_rate` and per-module `pass_rate` values
4. Classify the aggregate rate into a gate tier (G0-G4)
5. Evaluate INV-CCG-OVERALL: is aggregate rate >= 95%?
6. Evaluate INV-CCG-FAMILY-FLOOR: are all module rates >= 80%?
7. Evaluate INV-CCG-RATCHET: is the rate >= the previous run's rate?
8. Evaluate INV-CCG-REPRODUCIBILITY: are all evidence fields populated?
9. Emit CCG-001 (corpus run completed)
10. If all invariants hold: emit CCG-002 and allow the release
11. If any invariant fails: emit CCG-003 (and CCG-004 if regression) and block

## Corpus Maintenance

- New compatibility tests SHOULD be added when new API surface is implemented
- Tests MUST NOT be deleted to improve the pass rate; deletions require approval
- Flaky tests MUST be fixed or quarantined (quarantined tests count as skipped)
- The corpus SHOULD be run on every pull request for early signal
- The full gate evaluation runs on the release branch only

## Governance

The compatibility corpus gate is owned by the franken_node compatibility team.
Changes to thresholds or invariants require:

1. Written proposal with justification
2. Review by the project technical lead
3. Approval by two maintainers
4. Update to this policy document and the spec contract

Temporary threshold reductions are NOT permitted. The 95% aggregate and 80%
per-module floors are non-negotiable.

## Appeal Process

There is no waiver process for the aggregate threshold (INV-CCG-OVERALL).

For the per-module floor (INV-CCG-FAMILY-FLOOR), a time-limited exception may be
granted if ALL of the following conditions are met:

1. The module is newly added and has fewer than 10 total tests
2. The aggregate rate exceeds 97%
3. A remediation plan with a deadline is filed
4. The exception is approved by two maintainers
5. The exception expires within 14 calendar days

Exceptions are tracked in the corpus gate evidence for audit purposes.

## Monitoring

- Dashboard: corpus pass rate trend (aggregate and per-module)
- Alert on CCG-003 (gate blocked) via on-call notification
- Alert on CCG-004 (regression detected) via on-call notification
- Weekly report: corpus growth (new tests added), pass rate trend
- Monthly review: quarantined test inventory and remediation status

## Helpers

### `validate_corpus_result(result)`

Validates a corpus run result object against the schema. Returns a tuple of
`(valid, errors)` where `valid` is a boolean and `errors` is a list of strings.

### `pass_rate_to_tier(rate)`

Maps a numeric pass rate (0-100) to a gate tier string (G0-G4).

### `check_regression(current_rate, previous_rate)`

Compares current and previous pass rates. Returns `(is_regression, delta)`
where `is_regression` is True if the rate decreased and `delta` is the magnitude.
