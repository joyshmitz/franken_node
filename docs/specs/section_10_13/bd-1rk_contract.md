# bd-1rk: Lifecycle-Aware Health Gating and Rollout-State Persistence

## Section: 10.13 — FCP Deep-Mined Expansion Execution Track

## Decision

Every connector instance must satisfy a health gate before activation, and its
rollout state must be persisted so that restart and failover recover to the
same deterministic state. Recovery replay must reproduce the identical state
from a persisted snapshot.

## Dependencies

- bd-2gh: Connector lifecycle FSM (provides `ConnectorState` enum and `transition()`)

## Terminology

- **Health gate**: A set of preconditions (liveness, readiness, configuration validity)
  that must all pass before a connector can transition to `Active`.
- **Rollout state**: The combination of lifecycle state, health check results,
  activation timestamp, and rollout phase that defines a connector's operational status.
- **Persistence**: Serialization of rollout state to a durable store (JSON file)
  that survives process restart and can be loaded by a failover replica.
- **Recovery replay**: Loading persisted state and verifying it matches the
  expected state from the transition log.

## Health Gate Checks

| Check           | Description                                   | Required |
|-----------------|-----------------------------------------------|----------|
| `liveness`      | Connector process/thread is responsive        | yes      |
| `readiness`     | All dependencies are available                | yes      |
| `config_valid`  | Configuration passes schema validation        | yes      |
| `resource_ok`   | Resource limits (memory, handles) are within bounds | no |

## Rollout State Schema

```rust
pub struct RolloutState {
    pub connector_id: String,
    pub lifecycle_state: ConnectorState,
    pub health: HealthGateResult,
    pub rollout_phase: RolloutPhase,
    pub activated_at: Option<String>,   // ISO 8601
    pub persisted_at: String,           // ISO 8601
    pub version: u32,                   // monotonic for conflict detection
}
```

## Rollout Phases

| Phase     | Description                           |
|-----------|---------------------------------------|
| `shadow`  | Receiving traffic but not serving     |
| `canary`  | Serving a small fraction of traffic   |
| `ramp`    | Gradually increasing traffic share    |
| `default` | Fully active, serving all traffic     |

## Invariants

1. **INV-HEALTH-GATE**: Transition to `Active` requires all required health checks
   to pass. If any required check fails, the transition is rejected.
2. **INV-PERSIST-ATOMIC**: Rollout state writes are atomic — partial writes must not
   corrupt the persisted state.
3. **INV-PERSIST-VERSIONED**: Each persist increments a monotonic version counter.
   Stale writes (version < current) are rejected.
4. **INV-REPLAY-DETERMINISTIC**: Loading a persisted state and re-validating health
   produces the same gate decision when inputs are unchanged.
5. **INV-RESTART-RECOVERY**: After process restart, the connector resumes from the
   persisted lifecycle state, not from `Discovered`.

## Error Codes

| Code                    | Meaning                                         |
|-------------------------|--------------------------------------------------|
| `HEALTH_GATE_FAILED`    | One or more required health checks did not pass  |
| `PERSIST_STALE_VERSION` | Write rejected due to stale version counter      |
| `PERSIST_IO_ERROR`      | Could not write/read rollout state to/from store |
| `REPLAY_MISMATCH`       | Replayed state does not match persisted snapshot  |

## Artifacts

- `crates/franken-node/src/connector/health_gate.rs` — Health gate implementation
- `crates/franken-node/src/connector/rollout_state.rs` — Rollout state persistence
- `tests/integration/lifecycle_health_gate.rs` — Integration tests
- `artifacts/section_10_13/bd-1rk/rollout_state_replay.log` — Replay evidence
- `artifacts/section_10_13/bd-1rk/verification_evidence.json` — Gate evidence
- `artifacts/section_10_13/bd-1rk/verification_summary.md` — Human summary
