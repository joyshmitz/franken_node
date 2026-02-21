# bd-2ymp: Rollout Wedge Contract Field

## Scope

Define a mandatory contract field `rollout_wedge` for change proposals that
governs staged rollout decisions with deterministic gating. Every infrastructure
change that modifies runtime behaviour MUST declare a rollout wedge specifying
how the change will be progressively introduced and under what conditions it
will be rolled back.

## Section

11 -- Evidence and Decision Contracts

## Contract Field

Path: `change_proposal.rollout_wedge`

### Required Sub-fields

| Field | Type | Description |
|-------|------|-------------|
| `wedge_stages` | ordered list | Stages through which the rollout progresses |
| `initial_percentage` | integer 0-100 | Starting rollout percentage |
| `increment_policy` | enum | How percentage increases: `linear`, `exponential`, `manual` |
| `max_blast_radius` | integer 0-100 | Maximum infrastructure percentage affected at any point |
| `observation_window_hours` | float > 0 | Minimum hours to observe each stage before advancing |
| `wedge_state` | enum | Current state of the wedge |

### wedge_stages

Each stage entry MUST contain:

| Field | Type | Description |
|-------|------|-------------|
| `stage_id` | non-empty string | Unique identifier for the stage |
| `target_percentage` | integer 0-100 | Target rollout percentage for this stage |
| `duration_hours` | float > 0 | Planned duration of this stage in hours |
| `success_criteria` | non-empty list | Conditions that must hold for advancement |
| `rollback_trigger` | non-empty string | Condition that triggers automatic rollback |

Rules:
- At least 2 stages are required for any rollout.
- `target_percentage` values MUST be monotonically increasing across stages.
- The final stage MAY have `target_percentage` of 100.

### initial_percentage

- MUST be <= 10% for critical subsystems.
- MUST be > 0 (zero-traffic rollouts use shadow mode, not wedge).

### increment_policy

One of:
- `linear` -- percentage increases by a fixed delta per stage
- `exponential` -- percentage doubles (or similar geometric progression)
- `manual` -- operator must explicitly approve each stage transition

### max_blast_radius

- MUST be <= 25% for the first stage.
- MUST be <= the maximum `target_percentage` of any stage.
- If `max_blast_radius` is exceeded at any point, automatic rollback is triggered.

### observation_window_hours

- MUST be >= 1.0 hour per stage.
- The system MUST NOT advance to the next stage until the observation window
  has elapsed AND all success criteria are met.

### wedge_state

One of:
- `PENDING` -- wedge declared but rollout not started
- `ACTIVE` -- rollout in progress at some stage
- `PAUSED` -- rollout paused due to anomaly or operator hold
- `ROLLED_BACK` -- rollout reverted due to failure
- `COMPLETE` -- all stages completed successfully

## Invariants

| ID | Statement |
|----|-----------|
| INV-RWG-STAGED | All rollouts proceed through defined stages; no stage skipping |
| INV-RWG-OBSERVE | Each stage observed for minimum window before advancement |
| INV-RWG-BLAST | Blast radius never exceeds declared max_blast_radius |
| INV-RWG-ROLLBACK | Rollback triggers cause automatic reversion within 60s |

## Event Codes

| Code | Trigger |
|------|---------|
| RWG-001 | Rollout wedge stage advanced |
| RWG-002 | Rollout wedge paused (anomaly detected) |
| RWG-003 | Rollout wedge rolled back |
| RWG-004 | Rollout wedge completed |

## Thresholds

| Threshold | Value | Rationale |
|-----------|-------|-----------|
| Initial percentage (critical) | <= 10% | Limit blast radius of initial exposure |
| Minimum stages | >= 2 | Ensure at least one intermediate validation point |
| Observation window | >= 1 hour | Allow metrics to converge |
| First-stage blast radius | <= 25% | Limit damage from first-stage failures |
| Rollback execution time | <= 60 seconds | Minimize damage window |

## Validation Rules

1. `wedge_stages` is a non-empty list with at least 2 entries.
2. Each stage has all required fields with valid types.
3. `target_percentage` values are monotonically increasing.
4. `initial_percentage` is > 0 and <= first stage `target_percentage`.
5. `max_blast_radius` >= each stage `target_percentage` (or rollout is infeasible).
6. `observation_window_hours` >= 1.0.
7. `increment_policy` is one of the valid enum values.
8. `wedge_state` is one of the valid enum values.

## Helper Functions

### validate_rollout_wedge(wedge)

Accepts a dict representing a rollout wedge. Returns `(valid: bool, errors: list[str])`.
Checks all validation rules above.

### compute_total_rollout_duration(wedge)

Accepts a dict representing a rollout wedge. Returns the sum of all stage
`duration_hours` plus `observation_window_hours * len(stages)`.

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_11/bd-2ymp_contract.md` |
| Policy | `docs/policy/rollout_wedge.md` |
| Verification script | `scripts/check_rollout_wedge.py` |
| Python unit tests | `tests/test_check_rollout_wedge.py` |
| Verification evidence | `artifacts/section_11/bd-2ymp/verification_evidence.json` |
| Verification summary | `artifacts/section_11/bd-2ymp/verification_summary.md` |
