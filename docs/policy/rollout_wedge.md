# Rollout Wedge Policy

## Purpose

This policy mandates that every deployment-bearing change proposal explicitly
defines a rollout wedge -- a staged deployment strategy with deterministic
gating that controls blast radius, enforces observation windows, and provides
automatic rollback.

## Scope

All infrastructure changes that modify runtime behaviour within the franken_node
ecosystem. This includes connector deployments, control plane changes, policy
updates, and security patches.

## Risk Classification

**Priority:** P1 (Critical)
**Likelihood:** High -- incremental rollouts prevent catastrophic fleet-wide
failures.
**Impact:** Critical -- ungated deployments can cause full-fleet outages.

## Contract Requirements

### Mandatory Fields

Every change proposal MUST include a `rollout_wedge` field containing:

1. **wedge_stages** (minimum 2): Ordered deployment stages, each with:
   - `stage_id`: Unique identifier for the stage
   - `target_percentage`: Infrastructure percentage for this stage (0-100)
   - `duration_hours`: Planned duration of this stage
   - `success_criteria`: Conditions that must hold for advancement
   - `rollback_trigger`: Condition that triggers automatic rollback

2. **initial_percentage**: Starting rollout percentage (> 0, <= 10% for critical).

3. **increment_policy**: One of `linear`, `exponential`, `manual`.

4. **max_blast_radius**: Maximum infrastructure percentage affected at any point.

5. **observation_window_hours**: Minimum hours to observe each stage (>= 1.0).

6. **wedge_state**: One of `PENDING`, `ACTIVE`, `PAUSED`, `ROLLED_BACK`, `COMPLETE`.

### Staged Deployment Rules

- All rollouts MUST proceed through defined stages sequentially; no stage
  skipping is permitted (INV-RWG-STAGED).
- Each stage MUST be observed for at least the declared observation window
  before advancement (INV-RWG-OBSERVE).
- The blast radius MUST never exceed the declared `max_blast_radius` at any
  point during the rollout (INV-RWG-BLAST).
- Rollback triggers MUST cause automatic reversion within 60 seconds
  (INV-RWG-ROLLBACK).

### Blast Radius Controls

- Initial percentage MUST be <= 10% for critical subsystems.
- First-stage `target_percentage` MUST be <= 25%.
- `max_blast_radius` MUST be >= each stage `target_percentage`.
- Exceeding `max_blast_radius` triggers automatic rollback (RWG-003).

### Increment Policies

| Policy | Behaviour | Use Case |
|--------|-----------|----------|
| `linear` | Fixed delta per stage | Predictable, steady-state changes |
| `exponential` | Geometric increase per stage | Low-risk changes that can accelerate |
| `manual` | Operator approves each transition | High-risk or novel changes |

### Observation Windows

- Minimum observation window: 1.0 hour per stage.
- The system MUST NOT advance until both the observation window has elapsed AND
  all success criteria for the current stage are satisfied.
- If success criteria are not met within 3x the observation window, the rollout
  is automatically paused (RWG-002).

## Event Codes

| Code | Trigger |
|------|---------|
| RWG-001 | Rollout wedge stage advanced |
| RWG-002 | Rollout wedge paused (anomaly detected) |
| RWG-003 | Rollout wedge rolled back |
| RWG-004 | Rollout wedge completed |

## Invariants

| ID | Statement |
|----|-----------|
| INV-RWG-STAGED | All rollouts proceed through defined stages; no stage skipping |
| INV-RWG-OBSERVE | Each stage observed for minimum window before advancement |
| INV-RWG-BLAST | Blast radius never exceeds declared max_blast_radius |
| INV-RWG-ROLLBACK | Rollback triggers cause automatic reversion within 60s |

## Thresholds

| Threshold | Value |
|-----------|-------|
| Initial percentage (critical) | <= 10% |
| Minimum stages | >= 2 |
| Observation window | >= 1 hour |
| First-stage blast radius | <= 25% |
| Rollback execution time | <= 60 seconds |

## Governance

- Policy owner: Section 11 lead.
- Changes require review by at least one other section lead.
- Rollout wedge effectiveness is audited quarterly using incident data.

## Appeal Process

If a team believes their change does not require a multi-stage rollout:
1. File a waiver request documenting the rationale.
2. Waiver must be approved by the section lead and one additional reviewer.
3. Approved waivers are time-limited (max 90 days).
4. Waiver audit trail is included in the quarterly governance review.

## Audit Trail

All rollout wedge events (advancement, pause, rollback, completion) are
recorded with:
- Timestamp
- Stage ID and target percentage
- Event code (RWG-001 through RWG-004)
- Operator identity (for manual actions)
- Metric snapshot at decision point
