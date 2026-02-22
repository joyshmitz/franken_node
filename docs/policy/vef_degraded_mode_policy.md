# VEF Degraded-Mode Policy

**Bead**: bd-4jh9
**Section**: 10.18 — Verifiable Execution Fabric
**Track**: C (Trust-Native Ecosystem Layer)

## Overview

The Verifiable Execution Fabric (VEF) proof pipeline may experience lag or
complete outage due to resource constraints, backend failures, or burst
workloads. This policy defines how the system degrades safely in those
scenarios, ensuring operators always understand the trust posture.

## Degraded-Mode Tiers

| Tier | Proof Pipeline State | Action Policy | SLO Window |
|------|---------------------|---------------|------------|
| **Normal** | Healthy, proofs current | All actions allowed | N/A |
| **Restricted** | Lagging, within SLO | All actions allowed with audit annotation | proof_lag <= 300s, backlog <= 100, error_rate <= 0.10 |
| **Quarantine** | Lagging, exceeds SLO | High-risk blocked, low-risk with warning | proof_lag <= 900s, backlog <= 500, error_rate <= 0.30 |
| **Halt** | Down or critical lag | All VEF-gated actions blocked | proof_lag > 1800s or backlog > 1000 or error_rate > 0.50 or heartbeat > 60s |

## SLO Thresholds

### Restricted Tier
- Maximum proof lag: 300 seconds
- Maximum backlog depth: 100 pending jobs
- Maximum error rate: 10%

### Quarantine Tier
- Maximum proof lag: 900 seconds
- Maximum backlog depth: 500 pending jobs
- Maximum error rate: 30%

### Halt Tier (any one triggers)
- Proof lag exceeding quarantine threshold by 2x (1800s default)
- Backlog depth exceeding quarantine threshold by 2x (1000 default)
- Error rate exceeding 50%
- Proof pipeline heartbeat missed for > 60 seconds

## Transition Behavior

- **Escalation**: Immediate upon SLO breach. The system jumps directly to the
  appropriate tier (e.g., normal to halt if halt SLO is breached).
- **De-escalation**: Requires all metrics to be below the target tier's SLO
  thresholds for a stabilization window (default 120 seconds) before stepping
  down one tier.
- **Determinism**: Given the same sequence of metric observations, the system
  always produces the same sequence of mode transitions.

## Mandatory Audit Events

Every mode transition emits structured audit events:

| Code | Description |
|------|-------------|
| `VEF-DEGRADE-001` | Mode transition event with full context |
| `VEF-DEGRADE-002` | SLO breach detected with metric details |
| `VEF-DEGRADE-003` | Recovery initiated (stabilization window started) |
| `VEF-DEGRADE-004` | Recovery complete with receipt |
| `VEF-DEGRADE-ERR-001` | Transition failure |

## Recovery Receipts

Every de-escalation produces a receipt containing:
- Duration in degraded mode
- Count of affected actions (blocked or annotated)
- Which metric(s) triggered recovery
- Snapshot of all proof pipeline health metrics at recovery time

## Operator Guidance

1. **On restricted**: Investigate proof pipeline lag. Check scheduler queue and
   proof backend health. No immediate action required.
2. **On quarantine**: Escalate to on-call. High-risk operations are blocked.
   Investigate backend capacity and error sources.
3. **On halt**: Critical incident. All VEF-gated operations blocked.
   Emergency override available with operator acknowledgment and audit trail.

## Configuration

All thresholds are configurable via policy without code changes. See
`VefDegradedModeConfig` in the Rust implementation.
