# bd-3v8f Contract: Fallback Trigger

## Purpose

Define a mandatory, machine-verifiable contract field named
`change_summary.fallback_trigger` for subsystem proposals.

This field ensures each major subsystem change includes a deterministic
fallback trigger contract that specifies the conditions under which the
subsystem reverts to a known-safe state, the rollback mechanism, and the
associated timing guarantees.

## Section

11 — Evidence and Decision Contracts

## Contract Field

Path:
- `change_summary.fallback_trigger`

Required sub-fields:
1. `trigger_conditions` (list of strings) — deterministic conditions that activate fallback
2. `fallback_target_state` (string) — identifier of the validated safe state to revert to
3. `rollback_mechanism` (string in `{automatic, semi-automatic, manual}`)
4. `max_detection_latency_s` (number) — maximum seconds to detect trigger condition (must be <= 5)
5. `recovery_time_objective_s` (number) — maximum seconds to complete revert (must be <= 30)
6. `subsystem_id` (string) — canonical identifier of the subsystem
7. `rationale` (non-empty string) — justification for trigger selection

### trigger_conditions

A non-empty list of deterministic boolean predicates. Each predicate MUST
be machine-evaluable at runtime. Examples:
- `"health_check_failure_count >= 3 within 10s"`
- `"error_rate > 0.05 over 60s sliding window"`
- `"consensus_epoch_mismatch detected"`

### fallback_target_state

A string identifier referencing a validated safe state in the subsystem's
state registry. The target state MUST have been verified as safe through
at least one prior deployment cycle. Examples:
- `"v2.3.1-stable"`
- `"last_known_good_checkpoint"`
- `"genesis_state"`

### rollback_mechanism

The mechanism used to execute the revert:

| Mechanism | Description |
|-----------|-------------|
| automatic | System reverts without human intervention |
| semi-automatic | System prepares revert, human confirms |
| manual | Human initiates and executes revert |

Critical subsystems (availability > 99.9%) MUST use `automatic` rollback.

### max_detection_latency_s

The maximum number of seconds between the trigger condition becoming true
and the system detecting it. This value MUST be <= 5 seconds for all
subsystems. Lower values are required for higher-criticality subsystems.

| Criticality | Max Detection Latency |
|-------------|----------------------|
| Critical | <= 1s |
| High | <= 3s |
| Standard | <= 5s |

### recovery_time_objective_s

The maximum number of seconds from trigger detection to completion of
the revert to the fallback target state. This value MUST be <= 30 seconds.

| Criticality | Recovery Time Objective |
|-------------|------------------------|
| Critical | <= 5s |
| High | <= 15s |
| Standard | <= 30s |

## Subsystem Coverage

Fallback trigger contracts are required for 100% of critical subsystems.
A critical subsystem is any subsystem whose failure would:
- Cause data loss or corruption
- Violate security invariants
- Break consensus or coordination protocols
- Degrade availability below the SLA threshold

## Enforcement

Validator:
- `scripts/check_fallback_trigger.py`

Unit tests:
- `tests/test_check_fallback_trigger.py`

## Event Codes

| Code | Severity | Description |
|------|----------|-------------|
| FBT-001 | warning | Fallback triggered — subsystem reverting to safe state |
| FBT-002 | info | Fallback completed — subsystem successfully reverted |
| FBT-003 | critical | Fallback failed — revert did not complete within RTO |
| FBT-004 | warning | Manual override — operator bypassed automatic fallback |

## Invariants

| ID | Rule |
|----|------|
| INV-FBT-DETECT | Trigger detection completes within configured max_detection_latency_s |
| INV-FBT-REVERT | Revert completes within configured recovery_time_objective_s |
| INV-FBT-SAFE | Fallback target state is a validated safe state from the state registry |
| INV-FBT-AUDIT | All fallback events (trigger, complete, fail, override) are recorded with evidence |

## Thresholds

| Parameter | Constraint | Rationale |
|-----------|-----------|-----------|
| max_detection_latency_s | <= 5s | Ensures timely fault detection across all subsystem tiers |
| recovery_time_objective_s | <= 30s | Bounds worst-case downtime during rollback |
| fallback_coverage | 100% of critical subsystems | No critical subsystem may operate without a declared fallback |
| trigger_conditions | >= 1 per contract | Every contract must declare at least one trigger |

## Acceptance Criteria

1. Fallback trigger field is required on all subsystem change proposals.
2. Trigger conditions are a non-empty list of deterministic predicates.
3. Fallback target state references a validated safe state.
4. Rollback mechanism is one of {automatic, semi-automatic, manual}.
5. Max detection latency is a positive number <= 5 seconds.
6. Recovery time objective is a positive number <= 30 seconds.
7. All four event codes (FBT-001 through FBT-004) are emitted at appropriate points.
8. All four invariants (INV-FBT-DETECT, INV-FBT-REVERT, INV-FBT-SAFE, INV-FBT-AUDIT) are machine-verifiable.
9. 100% of critical subsystems have fallback trigger contracts.
10. Rationale is non-empty and explains trigger selection.
11. Validator rejects proposals with missing or invalid fallback triggers.
12. Manual overrides are logged with FBT-004 and require documented justification.
