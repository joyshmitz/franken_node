# bd-2nt Contract: VOI-Budgeted Monitor Scheduling

**Bead:** bd-2nt
**Section:** 10.11 (FrankenSQLite-Inspired Runtime Systems)
**Status:** Active

## Purpose

Implement Value of Information (VOI) budgeted scheduling for expensive
diagnostic operations.  Each diagnostic is scored by expected information
gain per unit compute cost, and a global budget constrains total spending.
Ensures the system always runs the most valuable diagnostics first within
its resource envelope.

## Diagnostic Registry

Each diagnostic has:

| Field               | Type      | Description                          |
|---------------------|-----------|--------------------------------------|
| name                | String    | Unique diagnostic name               |
| cost                | f64       | Estimated compute cost (abstract)    |
| wall_clock_ms       | u64       | Estimated wall-clock time in ms      |
| domains             | Vec       | Information domains answered         |
| staleness_tolerance | u64       | Max seconds before result is stale   |
| priority_class      | Enum      | Critical / Standard / Background     |

Minimum 10 registered diagnostics in the default set.

## VOI Scoring

The VOI score for a diagnostic is computed from four components:

| Component             | Weight | Description                              |
|-----------------------|--------|------------------------------------------|
| Staleness             | 0.3    | Higher if last result > staleness_tolerance |
| Uncertainty reduction | 0.3    | Higher after regime shifts (from bd-3u4) |
| Downstream impact     | 0.2    | Higher if gates downstream decisions     |
| Historical info       | 0.2    | EWMA of past actionable findings rate    |

Score = w_s * staleness + w_u * uncertainty + w_d * downstream + w_h * historical

## Budget Allocation

| Field              | Type  | Default | Description                         |
|--------------------|-------|---------|-------------------------------------|
| budget_units       | f64   | 1000.0  | Cost units per scheduling window    |
| window_secs        | u64   | 60      | Scheduling window in seconds        |
| storm_threshold    | f64   | 3.0     | Multiplier for storm detection      |
| storm_windows      | usize | 2       | Consecutive windows to trigger storm|
| regime_multiplier  | f64   | 2.0     | Budget multiplier after regime shift|
| regime_boost_secs  | u64   | 300     | Duration of regime boost in seconds |

Scheduler greedily selects diagnostics in descending VOI/cost order until
budget is exhausted.

## Priority Classes

| Class      | Preempts   | Description                          |
|------------|------------|--------------------------------------|
| Critical   | All others | Security-triggered validations       |
| Standard   | Background | Normal operational diagnostics       |
| Background | None       | Low-priority periodic checks         |

## Storm Protection

If diagnostic demand exceeds `storm_threshold * budget_units` for
`storm_windows` consecutive scheduling cycles, the scheduler enters
conservative mode: only Critical diagnostics run until demand drops below
budget.

## Event Codes

| Code    | Severity | Description                                        |
|---------|----------|----------------------------------------------------|
| VOI-001 | INFO     | Scheduling cycle completed                         |
| VOI-002 | INFO     | Diagnostic selected for execution                  |
| VOI-003 | INFO     | Diagnostic deferred (budget exhausted)             |
| VOI-004 | WARN     | Diagnostic preempted by higher priority             |
| VOI-005 | WARN     | Diagnostic storm detected, entering conservative   |
| VOI-006 | INFO     | Budget adjusted (regime shift or storm recovery)   |

## Invariants

- **INV-VOI-BUDGET** — Total diagnostic cost in any scheduling cycle never
  exceeds the effective budget (base or boosted).
- **INV-VOI-ORDER** — Diagnostics are selected in strictly descending
  VOI/cost order within each priority class.
- **INV-VOI-PREEMPT** — Critical diagnostics always execute before Standard
  and Background regardless of VOI score.
- **INV-VOI-STORM** — Conservative mode activates if and only if demand
  exceeds storm_threshold * budget for storm_windows consecutive cycles.

## Error Codes

| Code                       | Description                              |
|----------------------------|------------------------------------------|
| ERR_VOI_INVALID_CONFIG     | Configuration parameter out of range     |
| ERR_VOI_DUPLICATE_DIAG     | Duplicate diagnostic name in registry    |
| ERR_VOI_UNKNOWN_DIAG       | Referenced diagnostic not in registry    |
| ERR_VOI_BUDGET_EXCEEDED    | Budget constraint violated (internal)    |
| ERR_VOI_EMPTY_REGISTRY     | Scheduling with no registered diagnostics|

## Acceptance Criteria

1. Diagnostic registry with >= 10 registered diagnostics.
2. VOI scoring with staleness, uncertainty, downstream, historical components.
3. Greedy budget-constrained scheduler selects optimal set per cycle.
4. Preemption of lower-priority diagnostics by critical ones.
5. Storm protection at 3x budget for 2 consecutive windows.
6. Scheduling telemetry for every cycle with full decision trace.
7. Dynamic budget adjustment on regime shift from bd-3u4.
8. >= 30 unit tests.
9. Verification script passes all checks.

## Dependencies

- bd-3u4 (BOCPD regime detector) — triggers budget adjustment
- 10.13 telemetry namespace — event schema

## File Layout

```
docs/specs/section_10_11/bd-2nt_contract.md (this file)
crates/franken-node/src/connector/diagnostic_registry.rs
scripts/check_voi_scheduler.py
tests/test_check_voi_scheduler.py
artifacts/section_10_11/bd-2nt/verification_evidence.json
artifacts/section_10_11/bd-2nt/verification_summary.md
```
