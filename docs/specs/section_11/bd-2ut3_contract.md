# bd-2ut3 Contract: No-Contract-No-Merge Gate

## Purpose

Define a mandatory, machine-verifiable pre-merge gate that blocks merge for
subsystem changes unless a complete evidence contract is present and valid.

## Gate Scope

The gate applies when changed files include any subsystem paths:
- `crates/franken-node/src/**`
- `crates/franken-engine/src/**`
- `crates/asupersync/src/**`
- `services/**`

When applicable, at least one changed summary file under
`docs/change_summaries/*.json` MUST be present and valid.

## Required Contract Coverage

For each changed summary file, the gate validates `change_summary` plus these
required contract fields:

1. `compatibility_and_threat_evidence`
2. `ev_score_and_tier`
3. `expected_loss_model`
4. `fallback_trigger`
5. `rollout_wedge`
6. `rollback_command`
7. `benchmark_and_correctness_artifacts`

The gate also enforces core base fields:
- `intent`, `scope`, `surface_area_delta`, `affected_contracts`,
  `operational_impact`, `risk_delta`, `compatibility`, `dependency_changes`.

## Validity Requirements

- Missing required fields fail the gate.
- Invalid field content (e.g., malformed tiers, bad expected-loss aggregate,
  invalid rollback/fallback timing, empty benchmark/correctness lists) fails the gate.
- Referenced artifacts must exist on disk at declared paths.

## Escape Hatch (Audited)

A PR label `contract-override` may bypass failures.

Rules:
- Override is explicit and auditable.
- Gate output records `CONTRACT_NO_MERGE_OVERRIDE` with full error context.
- Override does not suppress evidence of missing/invalid fields; it only changes
  final pass/fail for emergency merge paths.

## Enforcement

Validator:
- `scripts/check_no_contract_no_merge.py`

Unit tests:
- `tests/test_check_no_contract_no_merge.py`

CI gate:
- `.github/workflows/no-contract-no-merge-gate.yml`

## Event Codes

- `CONTRACT_NO_MERGE_VALIDATED` (info)
- `CONTRACT_NO_MERGE_MISSING` (error)
- `CONTRACT_NO_MERGE_INCOMPLETE` (error)
- `CONTRACT_NO_MERGE_OVERRIDE` (warning)

## Acceptance Mapping

- Hard merge gate implemented as required pre-merge CI job.
- Gate checks all required field families, not just presence.
- Missing any single field fails validation.
- Override flow is label-based, explicit, and logged.
- Outputs are machine-readable for release and section-wide gates.
