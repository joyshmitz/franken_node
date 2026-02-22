# bd-5si Contract: Trust Fabric Convergence Protocol and Degraded-Mode Semantics

**Bead:** bd-5si
**Section:** 10.12 (Ecosystem Fabric + Network Effects)
**Status:** Active
**Owner:** CrimsonCrane

## Purpose

Implement a gossip-based convergence protocol for distributed trust state with
revocation-first priority, degraded-mode semantics, partition healing via delta
sync, and periodic anti-entropy sweeps. Every node in the fleet must operate
with a consistent, up-to-date trust state; this bead defines exactly how that
consistency is achieved and what happens when it cannot be.

## Trust State Vector

Each node maintains a trust state vector that captures its full trust posture:

| Field                       | Type              | Description                              |
|-----------------------------|-------------------|------------------------------------------|
| `version`                   | `u64`             | Monotonically increasing version number  |
| `digest`                    | `[u8; 32]`        | SHA-256 digest for fast comparison       |
| `active_trust_cards`        | `BTreeSet<String>`| Set of active trust card IDs             |
| `revocation_list_version`   | `u64`             | Revocation list version                  |
| `extension_auth_set`        | `BTreeSet<String>`| Set of authorized extension IDs          |
| `policy_checkpoint_epoch`   | `u64`             | Policy checkpoint epoch number           |
| `trust_anchor_fingerprints` | `BTreeSet<String>`| Set of trust anchor fingerprints         |

## Configuration

| Field                          | Type  | Default | Description                            |
|--------------------------------|-------|---------|----------------------------------------|
| `gossip_interval_ms`           | u64   | 1000    | Gossip round interval in milliseconds  |
| `gossip_fanout`                | usize | 3       | Number of peers per gossip round       |
| `convergence_timeout_secs`     | u64   | 30      | Max seconds to converge 1000-node fleet|
| `revocation_target_secs`       | u64   | 5       | Revocation propagation target (95%)    |
| `convergence_lag_threshold`    | u64   | 60      | Seconds of lag before degraded mode    |
| `max_degraded_secs`            | u64   | 300     | Max degraded before escalation (5 min) |
| `anti_entropy_interval_secs`   | u64   | 300     | Full-state anti-entropy sweep interval |
| `revocation_priority`          | bool  | true    | Prioritize revocation messages         |

## Event Codes

| Code    | Severity | Structured Log Event                       | Description                                |
|---------|----------|--------------------------------------------|--------------------------------------------|
| TFC-001 | INFO     | `trust_fabric.state_updated`               | Trust state vector updated                 |
| TFC-002 | WARN     | `trust_fabric.digest_mismatch`             | Digest mismatch detected with peer         |
| TFC-003 | INFO     | `trust_fabric.revocation_applied`          | Revocation applied via priority channel    |
| TFC-004 | WARN     | `trust_fabric.convergence_lag`             | Convergence lag exceeded threshold         |
| TFC-005 | WARN     | `trust_fabric.degraded_mode_entered`       | Degraded mode entered                      |
| TFC-006 | INFO     | `trust_fabric.degraded_mode_exited`        | Degraded mode exited                       |
| TFC-007 | INFO     | `trust_fabric.partition_healed`            | Partition healed, delta sync complete      |
| TFC-008 | INFO     | `trust_fabric.anti_entropy_sweep`          | Anti-entropy sweep completed               |

## Invariants

- **INV-TFC-MONOTONIC** -- Trust state version is strictly monotonically
  increasing; a node never accepts a state with version <= its current version
  (except during validated partition healing).
- **INV-TFC-REVOKE-FIRST** -- Revocations are always propagated and applied
  before authorizations in any update batch.
- **INV-TFC-DEGRADED-DENY** -- In degraded mode, all new trust decisions
  default to deny; only cached positive decisions within TTL are honored.
- **INV-TFC-CONVERGENCE** -- Under normal network conditions, the fleet
  converges within `convergence_timeout_secs` (default 30s for 1000 nodes).
- **INV-TFC-DIGEST** -- The state digest is a SHA-256 hash over canonical
  serialization of all state components.

## Error Codes

| Code                         | Description                              |
|------------------------------|------------------------------------------|
| ERR_TFC_INVALID_CONFIG       | Configuration parameter out of range     |
| ERR_TFC_STALE_STATE          | Received state older than local          |
| ERR_TFC_DIGEST_MISMATCH      | Trust state digests do not match         |
| ERR_TFC_DEGRADED_REJECT      | Artifact rejected in degraded mode       |
| ERR_TFC_ESCALATION_TIMEOUT   | Degraded mode exceeded max duration      |
| ERR_TFC_PARTITION_DETECTED   | Network partition detected               |

## Convergence Protocol

1. **Digest exchange**: Every `gossip_interval_ms`, each node sends its trust
   state vector digest to `gossip_fanout` random peers.
2. **Mismatch detection**: On digest mismatch, compare versions. The node with
   the older state pulls updates from the newer.
3. **State pull**: Pull delta between current version and peer version.
4. **Convergence bound**: O(log(N)) gossip rounds for N nodes.
5. **Revocation priority**: Revocations use a priority channel with full
   broadcast (fanout = N). Target: < 5 seconds to 95% of nodes.

## Degraded-Mode Semantics

When convergence lag exceeds `convergence_lag_threshold`:

1. **Conservative deny-by-default**: New trust decisions return DENY unless
   cached positive decision exists within TTL.
2. **No new artifacts**: New trust cards and extensions are rejected.
3. **Revocation continues**: Revocations processed from any available source.
4. **Status advertisement**: Node advertises degraded status to peers/operators.
5. **Escalation**: After `max_degraded_secs` (300s), escalate to supervision
   tree (bd-3he).

## Partition Healing

1. **Delta synchronization**: Only changes since partition are exchanged.
2. **Conflict resolution**: Higher version wins; revocations take precedence.
3. **Healing metrics logged**: partition duration, missed updates count,
   re-convergence time, delta size in bytes.

## Anti-Entropy Mechanism

1. Periodic full-state comparison at `anti_entropy_interval_secs`.
2. Merkle-tree digest over full trust state; sub-tree exchange on mismatch.
3. Complementary to gossip, not a replacement.

## Acceptance Criteria

1. Trust state vector type in `crates/franken-node/src/connector/trust_fabric.rs`
   with version, digest, and component sets.
2. Gossip-based convergence protocol converges simulated 100-node fleet within 30s.
3. Revocation-first priority channel ensures revocations propagate in < 5s to
   95% of nodes in simulation.
4. Convergence lag metric computed and reported per-node.
5. Degraded-mode semantics with conservative deny-by-default behavior.
6. Partition healing uses delta synchronization and logs healing metrics.
7. Anti-entropy sweep detects and repairs missed updates in simulation.
8. >= 30 unit tests covering all invariants.
9. Verification script `scripts/check_trust_fabric.py` passes all checks.
10. Evidence artifacts in `artifacts/section_10_12/bd-5si/`.

## Dependencies

- **bd-1l5** (trust object IDs) -- trust artifacts carry canonical IDs.
- **bd-3he** (supervision tree) -- degraded-mode timeout escalates to supervisor.
- **bd-cvt** (capability profiles) -- `cap:trust:read`, `cap:trust:write`.
- **10.13 telemetry namespace** -- convergence metrics conform to telemetry schema.
- **10.13 stable error namespace** -- convergence errors use registered codes.

## File Layout

```
docs/specs/section_10_12/bd-5si_contract.md   (this file)
docs/policy/trust_fabric_convergence.md
crates/franken-node/src/connector/trust_fabric.rs
scripts/check_trust_fabric.py
tests/test_check_trust_fabric.py
artifacts/section_10_12/bd-5si/verification_evidence.json
artifacts/section_10_12/bd-5si/verification_summary.md
```
