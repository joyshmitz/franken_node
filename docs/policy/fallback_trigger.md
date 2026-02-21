# Policy: Fallback Trigger Contract

**Bead:** bd-3v8f
**Section:** 11 — Evidence and Decision Contracts
**Status:** Active
**Last reviewed:** 2026-02-20

---

## 1. Overview

A fallback trigger is a deterministic condition that, when met, causes a
subsystem to revert to a known-safe state. Every major subsystem change
MUST declare a fallback trigger contract as part of the change proposal.

The contract ensures that subsystem failures are detected within a bounded
latency and that recovery completes within a bounded time objective,
preventing cascading failures and limiting blast radius.

## 2. Contract Requirements

Every `change_summary.fallback_trigger` object MUST include:

| Field | Type | Constraint |
|-------|------|-----------|
| trigger_conditions | list[string] | Non-empty; each condition is a deterministic predicate |
| fallback_target_state | string | References a validated safe state |
| rollback_mechanism | string | One of: automatic, semi-automatic, manual |
| max_detection_latency_s | number | > 0 and <= 5 |
| recovery_time_objective_s | number | > 0 and <= 30 |
| subsystem_id | string | Non-empty canonical subsystem identifier |
| rationale | string | Non-empty justification for trigger selection |

### 2.1 Trigger Conditions

Trigger conditions are boolean predicates that the runtime monitoring
system evaluates continuously. Each condition MUST be:

- **Deterministic**: Given the same system state, the predicate always
  returns the same result.
- **Observable**: The predicate references only metrics and state that
  the monitoring system can access.
- **Bounded**: The predicate includes explicit thresholds and time windows.

Examples of valid trigger conditions:
- `"health_check_failure_count >= 3 within 10s"`
- `"error_rate > 0.05 over 60s sliding window"`
- `"consensus_epoch_mismatch detected"`
- `"memory_usage > 0.95 for 30s"`

### 2.2 Fallback Target State

The fallback target state MUST be a previously validated safe state. A
state is considered validated if:

1. It was deployed to production for at least one release cycle without
   triggering any fallback.
2. It passed all conformance and integration tests.
3. It is recorded in the subsystem's state registry with a validation
   timestamp.

### 2.3 Rollback Mechanism

| Mechanism | When Required | Human Involvement |
|-----------|---------------|-------------------|
| automatic | Critical subsystems (availability > 99.9%) | None — system reverts autonomously |
| semi-automatic | High-priority subsystems | Human confirms prepared revert |
| manual | Standard subsystems | Human initiates and executes |

### 2.4 Timing Guarantees

The fallback trigger contract enforces two timing bounds:

- **max_detection_latency_s**: Maximum time from trigger condition
  becoming true to detection. MUST be <= 5 seconds.
- **recovery_time_objective_s**: Maximum time from detection to completed
  revert. MUST be <= 30 seconds.

Combined, the worst-case total recovery time is:
```
total_recovery <= max_detection_latency_s + recovery_time_objective_s <= 35s
```

### 2.5 Subsystem Coverage

Fallback trigger contracts are required for 100% of critical subsystems.
Non-critical subsystems SHOULD declare fallback triggers but are not
gated on them.

## 3. Thresholds

| Parameter | Bound | Enforcement |
|-----------|-------|-------------|
| max_detection_latency_s | <= 5s | Validator rejects proposals exceeding this bound |
| recovery_time_objective_s | <= 30s | Validator rejects proposals exceeding this bound |
| fallback_coverage | >= 100% critical | Gate blocks release if any critical subsystem lacks contract |
| trigger_conditions count | >= 1 | At least one trigger condition required per contract |

## 4. Validation

### 4.1 Contract Validation Rules

A fallback trigger object is valid if and only if:

1. `trigger_conditions` is a non-empty list of non-empty strings.
2. `fallback_target_state` is a non-empty string.
3. `rollback_mechanism` is one of `{automatic, semi-automatic, manual}`.
4. `max_detection_latency_s` is a positive number <= 5.
5. `recovery_time_objective_s` is a positive number <= 30.
6. `subsystem_id` is a non-empty string.
7. `rationale` is a non-empty string.

### 4.2 Example Valid Contract

```json
{
  "trigger_conditions": [
    "health_check_failure_count >= 3 within 10s",
    "error_rate > 0.05 over 60s sliding window"
  ],
  "fallback_target_state": "v2.3.1-stable",
  "rollback_mechanism": "automatic",
  "max_detection_latency_s": 2,
  "recovery_time_objective_s": 10,
  "subsystem_id": "connector-lifecycle",
  "rationale": "Connector lifecycle is critical for node availability. Three consecutive health check failures or sustained error rate indicate subsystem degradation requiring immediate rollback."
}
```

## 5. Governance

### 5.1 Threshold Adjustments

Timing thresholds may be adjusted through a formal governance process:

1. Proposal submitted as a bead with rationale and impact analysis.
2. At least 2 reviewers from different teams approve the change.
3. Impact analysis shows how existing contracts would be affected.
4. 14-day notice period before new thresholds take effect.
5. All existing contracts re-validated under new thresholds.

### 5.2 Appeal Process

Subsystem owners may appeal a fallback trigger rejection:

1. Appeal filed within 7 days of rejection.
2. Appellant provides justification for alternative timing bounds.
3. Review committee of 3 evaluates within 5 business days.
4. If approved, a time-bounded waiver is issued (max 90 days).
5. Waiver recorded with FBT-004 event code.

### 5.3 Audit Trail

All fallback events are recorded in an immutable audit log with:
- Timestamp (ISO 8601).
- Event code (FBT-001 through FBT-004).
- Subsystem identifier.
- Trigger condition that fired (for FBT-001).
- Fallback target state.
- Actual detection latency and recovery time.
- Outcome (success/failure).
- Actor identity (automated system or human operator).

## 6. Event Codes

| Code | Severity | Emitted When |
|------|----------|-------------|
| FBT-001 | warning | Fallback triggered — trigger condition detected, revert initiated |
| FBT-002 | info | Fallback completed — subsystem successfully reverted to safe state |
| FBT-003 | critical | Fallback failed — revert did not complete within RTO |
| FBT-004 | warning | Manual override — operator bypassed or overrode automatic fallback |

## 7. Invariants

| ID | Rule |
|----|------|
| INV-FBT-DETECT | Trigger detection completes within configured max_detection_latency_s |
| INV-FBT-REVERT | Revert completes within configured recovery_time_objective_s |
| INV-FBT-SAFE | Fallback target state is a validated safe state from the state registry |
| INV-FBT-AUDIT | All fallback events (trigger, complete, fail, override) are recorded with evidence |

## 8. Downgrade Triggers

A subsystem's fallback trigger contract may be flagged for review when:

| Trigger | Detection Method | Action |
|---------|-----------------|--------|
| Detection latency exceeded | Runtime monitoring detects latency > configured bound | FBT-003 emitted, incident review required |
| RTO exceeded | Runtime monitoring detects recovery > configured bound | FBT-003 emitted, postmortem required |
| Fallback target invalidated | Target state fails validation in newer test suite | Contract must be updated before next release |
| Coverage gap | New critical subsystem added without fallback contract | Release gate blocks deployment |
