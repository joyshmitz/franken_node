# bd-2yc4: Crash-Loop Detector with Automatic Rollback

## Bead: bd-2yc4 | Section: 10.13

## Purpose

Implements a crash-loop detector that monitors connector restart frequency,
triggers automatic rollback to a known-good pinned version when thresholds
are exceeded, and ensures rollback cannot bypass trust policy. All rollback
decisions are auditable with incident bundles.

## Invariants

| ID | Statement |
|----|-----------|
| INV-CLD-THRESHOLD | Crash-loop detection fires only when the configured threshold (count within window) is exceeded. |
| INV-CLD-ROLLBACK-AUTO | When a crash loop is detected, rollback to the known-good pin is automatic and immediate. |
| INV-CLD-TRUST-POLICY | Rollback targets must pass trust policy; rollback to an untrusted pin is forbidden. |
| INV-CLD-AUDIT | Every crash-loop detection and rollback decision produces an auditable incident record. |

## Types

### CrashLoopConfig
- `max_crashes: u32` — maximum crashes allowed within window.
- `window_secs: u64` — sliding window duration in seconds.
- `cooldown_secs: u64` — cooldown after rollback before re-detection.

### CrashEvent
- `connector_id: String`
- `timestamp: String`
- `reason: String`

### KnownGoodPin
- `connector_id: String`
- `version: String`
- `pin_hash: String`
- `trusted: bool`

### RollbackDecision
- `connector_id: String`
- `triggered: bool`
- `crash_count: u32`
- `window_secs: u64`
- `rollback_target: Option<KnownGoodPin>`
- `rollback_allowed: bool`
- `reason: String`
- `trace_id: String`
- `timestamp: String`

### CrashLoopIncident
- `connector_id: String`
- `crash_events: Vec<CrashEvent>`
- `decision: RollbackDecision`
- `trace_id: String`

## Error Codes

| Code | Trigger |
|------|---------|
| `CLD_THRESHOLD_EXCEEDED` | Crash count within window exceeded configured maximum. |
| `CLD_NO_KNOWN_GOOD` | No known-good pin available for rollback target. |
| `CLD_PIN_UNTRUSTED` | Known-good pin failed trust policy check. |
| `CLD_COOLDOWN_ACTIVE` | Crash-loop detected but cooldown period is still active. |

## Expected Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_13/bd-2yc4_contract.md` |
| Implementation | `crates/franken-node/src/runtime/crash_loop_detector.rs` |
| Integration tests | `tests/integration/crash_loop_rollback.rs` |
| Incident bundle | `artifacts/section_10_13/bd-2yc4/crash_loop_incident_bundle.json` |
| Verification evidence | `artifacts/section_10_13/bd-2yc4/verification_evidence.json` |
| Verification summary | `artifacts/section_10_13/bd-2yc4/verification_summary.md` |
