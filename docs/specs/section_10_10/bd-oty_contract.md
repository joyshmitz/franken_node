# bd-oty: Session-Authenticated Control Channel Integration

**Section:** 10.10 -- FCP-Inspired Hardening
**Status:** In Progress
**Owner:** CrimsonCrane
**Priority:** P2

## Overview

Enhancement Map 9E.6 mandates session-authenticated control traffic for all product control APIs. This bead integrates the canonical ControlChannel (bd-v97o) and KeyRoleRegistry (bd-364) into a unified session management layer wrapping all control API endpoints.

## Data Model

### SessionState (enum)
- `Establishing` -- handshake in progress
- `Active` -- session authenticated, traffic flowing
- `Terminating` -- graceful shutdown in progress
- `Terminated` -- session closed

### AuthenticatedSession
| Field | Type | Description |
|-------|------|-------------|
| `session_id` | `String` | Unique session identifier |
| `state` | `SessionState` | Current session lifecycle state |
| `client_identity` | `String` | Authenticated client principal |
| `server_identity` | `String` | Server identity |
| `encryption_key_id` | `String` | Key bound to Encryption role |
| `signing_key_id` | `String` | Key bound to Signing role |
| `established_at` | `u64` | UTC timestamp (ms) |
| `send_seq` | `u64` | Next outbound sequence number |
| `recv_seq` | `u64` | Next inbound sequence number |
| `replay_window` | `u64` | Configurable replay window size |

### SessionManager
Stateful manager tracking active sessions and enforcing lifecycle.

### SessionConfig
| Field | Type | Description |
|-------|------|-------------|
| `replay_window` | `u64` | Replay window size (default: 0 = strict) |
| `max_sessions` | `usize` | Maximum concurrent sessions |
| `session_timeout_ms` | `u64` | Session inactivity timeout |

### AuthenticatedMessage
| Field | Type | Description |
|-------|------|-------------|
| `session_id` | `String` | Owning session |
| `sequence` | `u64` | Per-direction monotonic sequence |
| `direction` | `Direction` | Send or Receive (from ControlChannel) |
| `payload_hash` | `String` | SHA-256 of payload |
| `signature` | `String` | Signature using Signing role key |

### SessionEvent
Structured audit event for session lifecycle and message processing.

## Invariants

- **INV-SCC-SESSION-AUTH**: Every control message requires an active authenticated session
- **INV-SCC-MONOTONIC**: Per-direction sequence numbers are strictly monotonic
- **INV-SCC-ROLE-KEYS**: Session uses Encryption key for exchange, Signing key for auth
- **INV-SCC-TERMINATED**: Terminated sessions reject all further messages

## Event Codes

| Code | Description |
|------|-------------|
| `SCC-001` | Session established |
| `SCC-002` | Authenticated message accepted |
| `SCC-003` | Message rejected (sequence/replay/auth) |
| `SCC-004` | Session terminated |

## Error Codes

| Code | Description |
|------|-------------|
| `ERR_SCC_NO_SESSION` | No active session for request |
| `ERR_SCC_SEQUENCE_VIOLATION` | Sequence monotonicity violated |
| `ERR_SCC_SESSION_TERMINATED` | Attempt to use terminated session |
| `ERR_SCC_ROLE_MISMATCH` | Wrong key role for operation |
| `ERR_SCC_AUTH_FAILED` | Authentication failed |
| `ERR_SCC_MAX_SESSIONS` | Maximum concurrent sessions reached |

## Acceptance Criteria

1. Every control API endpoint requires an active authenticated session.
2. Per-direction sequence monotonicity enforced: duplicate or regressed sequences rejected.
3. Replay window configurable (default=0 for strict monotonicity).
4. Session establishment uses Encryption role key for exchange, Signing role key for auth.
5. Terminated sessions reject all messages with ERR_SCC_SESSION_TERMINATED.
6. SessionManager tracks concurrent sessions with configurable limit.
7. All session events logged with trace_id and session_id.
8. Unit tests cover session lifecycle, sequence enforcement, replay window, role key usage.

## Upstream Dependencies

- bd-v97o: ControlChannel (per-direction sequence monotonicity, replay window)
- bd-364: KeyRoleRegistry (role-separated keys for session establishment)

## Downstream Dependents

- bd-2sx: Revocation freshness within authenticated sessions
- bd-1jjq: Section-wide verification gate

## Artifacts

- `docs/specs/section_10_10/bd-oty_contract.md` (this document)
- `crates/franken-node/src/api/session_auth.rs`
- `scripts/check_session_auth.py`
- `tests/test_check_session_auth.py`
- `artifacts/section_10_10/bd-oty/verification_evidence.json`
- `artifacts/section_10_10/bd-oty/verification_summary.md`
