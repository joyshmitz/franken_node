# Policy: Trust Fabric Convergence Protocol

**Bead:** bd-5si
**Section:** 10.12 (Ecosystem Fabric + Network Effects)
**Status:** Active

## 1. Overview

This policy governs how the franken_node fleet achieves and maintains
consistent trust state across all nodes. The trust fabric convergence protocol
ensures that revocation events, trust card updates, extension authorizations,
and policy checkpoint changes propagate to all nodes within bounded time.

## 2. Convergence Requirements

### 2.1 Normal Operation

- All nodes MUST participate in the gossip-based convergence protocol.
- Gossip rounds occur every 1 second with fanout of 3 peers.
- A 1000-node fleet MUST converge within 30 seconds under normal conditions.
- Each node computes and reports its convergence lag as a health metric.

### 2.2 Revocation-First Execution

- Revocations MUST be propagated before authorizations in every update batch.
- Revocations use a priority channel with full-broadcast fanout.
- Target: 95% of nodes receive revocations within 5 seconds.
- A node MUST immediately apply a received revocation, even without full state.

### 2.3 State Vector Integrity

- The trust state vector carries a monotonically increasing version number.
- The SHA-256 digest covers the canonical serialization of all state components.
- A node MUST reject any state vector with a version <= its current version.
- State vector comparison uses the digest for fast equality checks.

## 3. Degraded-Mode Policy

### 3.1 Entry Conditions

A node enters degraded mode when:
- Convergence lag exceeds the threshold (default: 60 seconds).
- Network partition is detected (no reachable peers).
- Upstream trust authority is unreachable.

### 3.2 Degraded-Mode Behavior

While in degraded mode:

1. **Deny by default**: All new trust decisions return DENY unless a cached
   positive decision exists and its TTL has not expired.
2. **No new artifacts accepted**: New trust cards and extensions are rejected
   with error code `ERR_TFC_DEGRADED_REJECT`.
3. **Revocations still processed**: Revocations from any available source
   (local cache, peer gossip, direct push) continue to be applied.
4. **Status advertisement**: The node advertises degraded status via health
   metrics and peer gossip.
5. **Operator notification**: Degraded mode entry triggers an alert.

### 3.3 Escalation

- If degraded mode persists beyond the maximum duration (default: 300s / 5
  minutes), the node escalates to the supervision tree (bd-3he).
- Escalation error code: `ERR_TFC_ESCALATION_TIMEOUT`.
- The supervision tree determines whether to restart, isolate, or shut down.

### 3.4 Recovery

- A node exits degraded mode when convergence lag drops below the threshold.
- On recovery, the node performs a delta sync to catch up on missed updates.
- Recovery is logged with event code TFC-006.

## 4. Partition Healing

### 4.1 Delta Synchronization

- When a partition heals, nodes exchange only the trust state changes that
  occurred during the partition.
- Full state transfer is used only as a fallback when delta is unavailable.

### 4.2 Conflict Resolution

- Higher version number wins in all conflicts.
- Revocations always take precedence over authorizations regardless of version.

### 4.3 Healing Metrics

The following metrics MUST be logged on partition heal:
- Partition duration (seconds)
- Number of missed updates
- Time to re-convergence (seconds)
- Delta size (bytes)

## 5. Anti-Entropy

- A full-state anti-entropy sweep runs every 300 seconds (configurable).
- The sweep uses Merkle-tree digests for efficient difference detection.
- Any discrepancies found are corrected by targeted sub-tree exchange.
- Anti-entropy is complementary to gossip; it catches rare missed updates.

## 6. Monitoring and Alerting

### 6.1 Health Metrics

- `trust_fabric.convergence_lag_secs`: Current convergence lag per node.
- `trust_fabric.gossip_rounds_to_converge`: Rounds needed in last convergence.
- `trust_fabric.degraded_mode_active`: Boolean, true if node is degraded.
- `trust_fabric.revocation_propagation_time_ms`: Time for last revocation.
- `trust_fabric.anti_entropy_corrections`: Count of corrections per sweep.

### 6.2 Dashboard

A trust fabric dashboard MUST display:
- Fleet-wide convergence status
- Per-node convergence lag distribution
- Degraded-mode node count
- Revocation propagation latency histogram
- Anti-entropy correction velocity

### 6.3 Alerts

| Alert                       | Threshold                    | Severity |
|-----------------------------|------------------------------|----------|
| Convergence lag high        | > 60 seconds                 | WARNING  |
| Degraded mode entered       | Any node                     | WARNING  |
| Degraded mode escalation    | > 300 seconds in degraded    | CRITICAL |
| Anti-entropy corrections    | > 0 in sweep                 | INFO     |
| Partition detected          | Any partition event          | WARNING  |

## 7. Review and Evidence

- This policy MUST be reviewed when convergence protocol changes.
- Evidence of convergence testing MUST be captured in verification artifacts.
- Simulation results with partition injection MUST be documented.
