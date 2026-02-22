# bd-2wsm: Epoch Transition Barrier Protocol — Spec Contract

**Section:** 10.14 | **Bead:** bd-2wsm | **Status:** Active

## Purpose

Implements the epoch transition barrier: the coordination protocol ensuring all
core services drain in-flight work and acknowledge readiness before committing
to a new epoch. Without a barrier, split-brain conditions arise where some
services operate under epoch N while others have moved to epoch N+1.

## Protocol Phases

| Phase    | Description                                       | Next (success) | Next (failure) |
|----------|---------------------------------------------------|----------------|----------------|
| Proposed | Leader announces intent to transition              | Draining       | —              |
| Draining | Each participant drains in-flight work, sends ACK  | Committed      | Aborted        |
| Committed| All ACKs received; epoch advanced atomically       | —              | —              |
| Aborted  | Timeout or drain failure; epoch stays at current   | —              | —              |

## Invariants

- **INV-BARRIER-ALL-ACK**: commit requires drain ACKs from every registered participant
- **INV-BARRIER-NO-PARTIAL**: after barrier completes, system is in exactly one epoch
- **INV-BARRIER-ABORT-SAFE**: on abort, no participant operates under the new epoch
- **INV-BARRIER-SERIALIZED**: concurrent barrier attempts are rejected
- **INV-BARRIER-TRANSCRIPT**: every barrier produces a complete audit transcript
- **INV-BARRIER-TIMEOUT**: missing ACKs within timeout trigger abort path

## Event Codes

| Code                          | Description                              |
|-------------------------------|------------------------------------------|
| BARRIER_PROPOSED              | Barrier proposed by leader               |
| BARRIER_DRAIN_ACK             | Participant drain acknowledgement        |
| BARRIER_COMMITTED             | Epoch transition committed               |
| BARRIER_ABORTED               | Barrier aborted                          |
| BARRIER_TIMEOUT               | Participant timeout triggered            |
| BARRIER_DRAIN_FAILED          | Participant drain operation failed       |
| BARRIER_ABORT_SENT            | Abort notification sent to participant   |
| BARRIER_CONCURRENT_REJECTED   | Concurrent barrier attempt rejected      |
| BARRIER_TRANSCRIPT_EXPORTED   | Transcript exported for audit            |
| BARRIER_PARTICIPANT_REGISTERED| Participant registered for coordination  |

## Error Codes

| Code                            | Description                          |
|---------------------------------|--------------------------------------|
| ERR_BARRIER_CONCURRENT          | Another barrier already active       |
| ERR_BARRIER_NO_PARTICIPANTS     | No participants registered           |
| ERR_BARRIER_TIMEOUT             | Drain timeout exceeded               |
| ERR_BARRIER_DRAIN_FAILED        | Participant drain failed             |
| ERR_BARRIER_ALREADY_COMPLETE    | Operation on terminal barrier        |
| ERR_BARRIER_INVALID_PHASE       | Invalid phase transition             |
| ERR_BARRIER_UNKNOWN_PARTICIPANT | Unknown participant ID               |
| ERR_BARRIER_EPOCH_MISMATCH      | Target epoch != current + 1          |

## Dependencies

- **bd-3hdv**: Monotonic control epoch (epoch_advance used for commit)
- **bd-2xv8**: Fail-closed validity window (epoch scoping)
- **bd-3cs3**: Epoch-scoped key derivation (barrier authentication)

## Trace Format

JSONL via `BarrierTranscript::export_jsonl()` with fields:
`event_code`, `barrier_id`, `timestamp_ms`, `detail`, `trace_id`.

Schema version: `eb-v1.0`
