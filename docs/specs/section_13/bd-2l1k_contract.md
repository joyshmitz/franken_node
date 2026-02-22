# bd-2l1k Contract: 100% Replay Artifact Coverage Gate

## Goal

Enforce a hard release gate requiring complete replay artifact coverage for all
enumerated high-severity incident types, with deterministic reproduction
evidence and machine-verifiable artifact completeness.

## Quantified Invariants

- `INV-RCG-COVERAGE`: Replay coverage ratio is exactly `1.0` (`100%`), computed
  as `covered_incident_types / required_incident_types`.
- `INV-RCG-ENUMERATION`: Required high-severity incident types are:
  - `rce`
  - `privilege_escalation`
  - `data_exfiltration`
  - `sandbox_escape`
  - `trust_system_bypass`
  - `supply_chain_compromise`
  - `denial_of_service`
  - `memory_corruption`
- `INV-RCG-ARTIFACT-PRESENCE`: Every required incident type has a replay
  artifact path that exists on disk.
- `INV-RCG-REPLAY-CONTENT`: Every replay artifact includes initial state
  snapshot, input sequence, expected behavior trace, actual behavior trace, and
  divergence point.
- `INV-RCG-DETERMINISM`: Each replay artifact is verified with at least `10`
  deterministic runs and `deterministic_match=true`.
- `INV-RCG-SLA`: New incident types must receive replay artifacts within `1`
  sprint (`<= 14 days`) from discovery.
- `INV-RCG-DETERMINISTIC-GATE`: Reordering matrix entries does not change
  computed coverage ratio or verdict.

## Required Data Contract

`artifacts/13/replay_coverage_matrix.json` must include:

- Metadata:
  - `bead_id`
  - `generated_at_utc`
  - `trace_id`
  - `minimum_required_coverage_ratio`
  - `new_incident_type_sla_days`
- Incident-type enumeration:
  - `required_incident_types[]`
- Coverage matrix records (`replay_artifacts[]`) with required fields:
  - `incident_type`
  - `artifact_path`
  - `last_verified_utc`
  - `deterministic_runs`
  - `deterministic_match`
  - `initial_state_snapshot`
  - `input_sequence`
  - `expected_behavior_trace`
  - `actual_behavior_trace`
  - `divergence_point`
  - `reproduction_command`
  - `discovered_at_utc`
- Aggregated coverage summary:
  - `required_count`
  - `covered_count`
  - `coverage_ratio`

## Determinism and Adversarial Checks

- Gate recomputes required/covered counts from matrix records and verifies
  declared summary values.
- Gate must recompute coverage on reordered entries and yield identical verdict.
- Gate performs adversarial perturbation check by removing one required incident
  type coverage and confirming verdict flips to failure.

## Required Scenarios

1. **Pass scenario**: All required incident types are covered and deterministic
   replay checks pass.
2. **Coverage-fail scenario**: Missing any required incident type blocks gate.
3. **Content-fail scenario**: Missing required replay content field blocks gate.
4. **Determinism-fail scenario**: `deterministic_runs < 10` or mismatch flag
   blocks gate.
5. **SLA-fail scenario**: Incident discovered more than 14 days ago without
   valid artifact blocks gate.

## Structured Event Codes

- `RCG-001`: Replay coverage metrics computed.
- `RCG-002`: Replay coverage gate passed (`100%`).
- `RCG-003`: Replay coverage gate failed (`<100%`).
- `RCG-004`: Missing required incident-type coverage.
- `RCG-005`: Replay artifact content/completeness violation.
- `RCG-006`: Determinism validation executed.
- `RCG-007`: New-incident SLA validation executed.

All events include stable `trace_id`.

## Gate Decision Flow

1. Load and validate `replay_coverage_matrix.json`.
2. Validate required incident enumeration and matrix schema.
3. Verify artifact file existence for each record.
4. Verify replay content fields and determinism requirements.
5. Verify SLA for newly discovered incident types.
6. Recompute coverage ratio and summary metrics.
7. Validate determinism under reordered matrix entries.
8. Run adversarial perturbation check.
9. Emit structured events and pass/fail verdict.
