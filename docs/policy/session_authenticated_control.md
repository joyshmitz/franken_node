# Session-Authenticated Control Channel Policy

**Policy ID:** POL-SAC-001
**Section:** 10.10 (FCP-Inspired Hardening)
**Bead:** bd-oty
**Effective:** 2026-02-21
**Owner:** CrimsonCrane

## 1. Purpose

This policy establishes the rules for session-authenticated control
channels in the franken_node control plane. It ensures that every control
API endpoint operates within an authenticated session with monotonic
anti-replay framing, preventing replay attacks and unauthorized control
message injection.

## 2. Scope

Applies to all control-plane API traffic within the three-kernel
architecture (franken_engine, asupersync, franken_node), including fleet
control, operator, verifier, and trust-card API route groups.

## 3. Definitions

- **Authenticated Session:** A stateful connection between a client and
  server that binds identity, cryptographic keys, and per-direction
  sequence counters.
- **Session Lifecycle:** The progression through Establishing, Active,
  Terminating, and Terminated states.
- **Monotonic Sequence:** A per-direction counter that must strictly
  increase with each message (strict mode) or remain within a sliding
  window (windowed mode).
- **Replay Window:** A configurable parameter (default: 0 = strict
  monotonicity) that determines how many out-of-order messages are
  tolerated.
- **Session Binding:** The requirement that the action dispatcher
  verifies an authenticated session before executing any control action.

## 4. Session Establishment Rules

1. Every session MUST be established via `establish_session()` before any
   control messages are accepted (INV-SCC-SESSION-AUTH).
2. Session establishment MUST bind an Encryption role key for key
   exchange and a Signing role key for message authentication
   (INV-SCC-ROLE-KEYS).
3. Role key assignments MUST be validated via `validate_key_roles()`
   before session activation.
4. The system MUST enforce a configurable maximum concurrent session
   limit (default: 256). Attempts to exceed this limit MUST be rejected
   with ERR_SCC_MAX_SESSIONS.

## 5. Message Processing Rules

1. Every control message MUST be processed within an active session.
   Messages for non-existent sessions are rejected with ERR_SCC_NO_SESSION.
2. Per-direction sequence numbers MUST be strictly monotonic
   (INV-SCC-MONOTONIC).
3. In strict mode (replay_window=0), the sequence number MUST exactly
   equal the next expected value.
4. In windowed mode (replay_window>0), the sequence number MUST fall
   within the sliding window and MUST NOT have been seen before.
5. Duplicate sequences within the replay window MUST be rejected as
   replays (ReplayDetected error).

## 6. Session Termination Rules

1. Terminated sessions MUST reject all further messages with
   ERR_SCC_SESSION_TERMINATED (INV-SCC-TERMINATED).
2. Session termination MUST clean up associated replay windows.
3. Termination MUST emit a SCC-004 event with trace_id correlation.

## 7. Event Codes

| Code    | Description                                  |
|---------|----------------------------------------------|
| SCC-001 | Session successfully established              |
| SCC-002 | Authenticated message accepted                |
| SCC-003 | Message rejected (sequence/replay/auth)       |
| SCC-004 | Session terminated                            |

## 8. Error Codes

| Code                       | Description                            |
|----------------------------|----------------------------------------|
| ERR_SCC_NO_SESSION         | No active session for request          |
| ERR_SCC_SEQUENCE_VIOLATION | Sequence monotonicity violated         |
| ERR_SCC_SESSION_TERMINATED | Attempt to use terminated session      |
| ERR_SCC_ROLE_MISMATCH      | Wrong key role for operation           |
| ERR_SCC_AUTH_FAILED        | Authentication failed                  |
| ERR_SCC_MAX_SESSIONS       | Maximum concurrent sessions reached    |

## 9. Invariants

- **INV-SCC-SESSION-AUTH:** Every control message requires an active
  authenticated session.
- **INV-SCC-MONOTONIC:** Per-direction sequence numbers are strictly
  monotonic within a session.
- **INV-SCC-ROLE-KEYS:** Session uses Encryption key for exchange,
  Signing key for authentication.
- **INV-SCC-TERMINATED:** Terminated sessions reject all further messages.

## 10. Audit Requirements

All session lifecycle events (establish, accept, reject, terminate) MUST
be emitted as structured log events with trace_id and session_id
correlation for audit trail reconstruction.

## 11. Upstream Dependencies

- **bd-v97o:** ControlChannel providing per-direction sequence
  monotonicity and replay-window primitives.
- **bd-364:** KeyRoleRegistry providing role-separated keys for session
  establishment.

## 12. Compliance

Verification is automated via `scripts/check_session_auth.py --json`.
Evidence is stored at `artifacts/section_10_10/bd-oty/verification_evidence.json`.
