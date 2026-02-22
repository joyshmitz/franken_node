# bd-1vsr: Transition Abort Semantics — Spec Contract

**Section:** 10.14 | **Bead:** bd-1vsr | **Status:** Active

## Purpose

Defines the abort semantics for epoch transition barriers: when a barrier times
out or receives a cancellation signal, all participants revert to the current
epoch with no partial state. An explicit `ForceTransitionPolicy` allows scoped
override for exceptional cases (e.g., disaster recovery).

## Abort Semantics

| Trigger               | Default Behavior          | With Force Policy          |
|-----------------------|---------------------------|----------------------------|
| Timeout               | Abort, stay at current epoch | Force commit if policy valid |
| Cancellation          | Abort, stay at current epoch | Force commit if policy valid |
| Participant failure   | Abort, stay at current epoch | Force commit if policy valid |

## Force Transition Policy Schema

| Field                   | Type          | Description                           |
|------------------------|---------------|---------------------------------------|
| skippable_participants | Set<String>   | Named participants that may be skipped |
| max_skippable          | usize         | Maximum number of skippable participants |
| operator_id            | String        | Operator identity (must be non-empty)  |
| audit_reason           | String        | Reason for force override (must be non-empty) |

## Invariants

- **INV-ABORT-NO-PARTIAL**: after abort, system is in exactly the pre-transition epoch
- **INV-ABORT-ALL-NOTIFIED**: all participants receive abort notification
- **INV-ABORT-FORCE-EXPLICIT**: force policy must be explicitly constructed (no default)
- **INV-ABORT-FORCE-SCOPED**: force policy names specific skippable participants
- **INV-ABORT-FORCE-AUDITED**: every force override is logged with operator identity
- **INV-ABORT-FORCE-BOUNDED**: skipped participants cannot exceed max_skippable

## Event Codes

| Code                          | Description                           |
|-------------------------------|---------------------------------------|
| TRANSITION_ABORTED            | Transition aborted                    |
| FORCE_TRANSITION_APPLIED      | Force transition applied              |
| TRANSITION_ABORT_REJECTED     | Abort request rejected                |
| ABORT_PARTICIPANT_NOTIFIED    | Participant notified of abort         |
| FORCE_POLICY_VALIDATED        | Force policy validation passed        |
| FORCE_POLICY_REJECTED         | Force policy validation failed        |
| ABORT_EPOCH_CONFIRMED         | Post-abort epoch confirmed            |
| FORCE_EPOCH_ADVANCED          | Epoch advanced via force policy       |
| ABORT_EVENT_PERSISTED         | Abort event persisted to store        |
| ABORT_RETRY_ALLOWED           | Retry permitted after abort           |

## Error Codes

| Code                          | Description                           |
|-------------------------------|---------------------------------------|
| ERR_ABORT_NO_BARRIER          | No active barrier to abort            |
| ERR_FORCE_NO_OPERATOR         | Force policy missing operator_id      |
| ERR_FORCE_NO_REASON           | Force policy missing audit_reason     |
| ERR_FORCE_OVER_LIMIT          | Skipped count exceeds max_skippable   |
| ERR_FORCE_UNKNOWN_PARTICIPANT | Skippable participant not registered  |
| ERR_ABORT_ALREADY_TERMINAL    | Barrier already terminal              |
| ERR_FORCE_ALL_SKIPPED         | Cannot skip all participants          |
| ERR_ABORT_INVALID_EPOCH       | Epoch mismatch                        |

## Dependencies

- **bd-2wsm**: Epoch transition barrier (this bead defines abort semantics for it)

## Trace Format

JSONL via `TransitionAbortManager::export_audit_log_jsonl()` with fields:
`event_code`, `barrier_id`, `pre_epoch`, `proposed_epoch`, `outcome`,
`reason`, `timestamp_ms`, `trace_id`, `schema_version`.

Schema version: `ta-v1.0`
