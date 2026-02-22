# ATC Degraded/Offline Mode Contract

## Scope

This contract defines deterministic degraded/offline behavior for ATC
(Adversarial Trust Commons) federation paths when federation connectivity
or federation health is unavailable.

## Objectives

1. Federation outage/partition must trigger deterministic fallback.
2. Local risk controls must remain functional in degraded/suspended modes.
3. Rejoin/reconciliation must be auditable and deterministic.

## Trigger Conditions

- `capability_unavailable:federation_peer`
- `health_gate_failed:federation_sync`

## Runtime States

- `normal`: federation available, all controls active.
- `degraded`: federation path constrained; local risk controls continue.
- `suspended`: prolonged degraded interval exceeded; only essential local
  controls permitted.

## Local-First Fallback Policy

When degraded mode is entered due to federation outage/partition:

- Denied (federation-bound): `federation.sync`, `federation.publish`
- Permitted (local controls): `risk.local_assess`, `health.check`

This preserves local control-plane safety actions while preventing unsafe
federated writes during partition.

## Recovery/Rejoin Criteria

All criteria must hold, then remain stable through a stabilization window:

- `capability_available:federation_peer`
- `health_gate_restored:federation_sync`
- `error_rate_below:0.05` over recovery window

If criteria hold continuously for the stabilization window, mode exits to
`normal`.

## Audit Requirements

Required event codes for traceability:

- `TRUST_INPUT_STALE`
- `DEGRADED_MODE_ENTERED`
- `DEGRADED_ACTION_BLOCKED` / `DEGRADED_ACTION_ANNOTATED`
- `TRUST_INPUT_REFRESHED`
- `DEGRADED_MODE_EXITED`
- `DEGRADED_MODE_SUSPENDED` (if max degraded duration exceeded)

All events must include stable timestamps and trace IDs for replay/audit.

## Determinism

For identical:

- trigger sequence,
- timestamps,
- recovery signals,
- action inputs,

the resulting event stream and mode transitions must be byte-identical.

## Validation Surface

- Integration test: `tests/integration/atc_partition_fallback.rs`
- Artifact event stream: `artifacts/10.19/atc_degraded_mode_events.jsonl`

