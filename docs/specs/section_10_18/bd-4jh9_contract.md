# bd-4jh9: VEF Degraded-Mode Policy for Proof Lag/Outage

**Section**: 10.18 — Verifiable Execution Fabric
**Type**: Resilience policy
**Status**: Active

## Purpose

Define deterministic degraded-mode policies for the Verifiable Execution Fabric (VEF)
when the proof pipeline experiences lag or outage. Three tiers (`restricted`,
`quarantine`, `halt`) provide graduated responses with explicit SLOs, mandatory
audit events, and recovery receipts.

## Degraded-Mode Tiers

### Normal

Proof pipeline is healthy. All VEF-gated actions proceed without restriction.

### Restricted (Tier 1)

Proof pipeline is lagging but within SLO tolerance.

- **Semantics**: Actions proceed with enhanced monitoring and audit trail.
- **SLO thresholds** (default, configurable):
  - `max_proof_lag_secs`: 300 (oldest unproven window age)
  - `max_backlog_depth`: 100 (pending proof jobs)
  - `max_error_rate`: 0.10 (proof generation error rate over window)
- **Action policy**: All actions permitted; high-risk actions annotated with
  degraded-mode warning in audit log.

### Quarantine (Tier 2)

Proof pipeline lag exceeds SLO threshold.

- **Semantics**: High-risk actions are blocked; low-risk actions proceed with
  warnings.
- **SLO thresholds** (default, configurable):
  - `max_proof_lag_secs`: 900
  - `max_backlog_depth`: 500
  - `max_error_rate`: 0.30
- **Action policy**: High-risk actions (policy changes, key rotations,
  trust boundary modifications) are denied. Read-only and health operations
  are permitted with audit annotation.

### Halt (Tier 3)

Proof pipeline is down or critically lagged.

- **Semantics**: All VEF-gated actions are blocked until recovery.
- **SLO thresholds** (triggers on any):
  - `proof_lag_secs` exceeds quarantine threshold by 2x, OR
  - `backlog_depth` exceeds quarantine threshold by 2x, OR
  - `error_rate` exceeds 0.50, OR
  - proof pipeline heartbeat missed for > 60s
- **Action policy**: Only health-check and emergency-override (with operator
  acknowledgment) are permitted.

## Transition Rules

All transitions are deterministic: identical metric sequences always produce
identical mode transitions.

```
normal -> restricted:  any metric breaches restricted SLO
normal -> quarantine:  any metric breaches quarantine SLO (skip restricted)
normal -> halt:        any metric breaches halt SLO (skip restricted+quarantine)
restricted -> quarantine: any metric breaches quarantine SLO
restricted -> halt:       any metric breaches halt SLO
quarantine -> halt:       any metric breaches halt SLO
halt -> quarantine:    all metrics recover below halt SLO, stabilization window met
quarantine -> restricted: all metrics recover below quarantine SLO, stabilization window met
restricted -> normal:  all metrics recover below restricted SLO, stabilization window met
```

Transitions always escalate immediately but de-escalate only after a
configurable stabilization window (default: 120s).

## Proof Lag Metrics

| Metric | Type | Source |
|--------|------|--------|
| `proof_lag_secs` | Duration | Age of oldest unproven execution window |
| `backlog_depth` | Count | Number of pending proof jobs in scheduler |
| `error_rate` | Float [0,1] | Proof generation error rate over sliding window |
| `heartbeat_age_secs` | Duration | Time since last proof pipeline heartbeat |

## Audit Events

Every mode transition emits a structured audit event:

- `VEF-DEGRADE-001`: Mode transition — includes current mode, target mode,
  triggering metric, metric value, SLO threshold, timestamp, correlation ID.
- `VEF-DEGRADE-002`: SLO breach detected — includes metric name, observed
  value, threshold, tier.
- `VEF-DEGRADE-003`: Recovery initiated — stabilization window started.
- `VEF-DEGRADE-004`: Recovery complete — includes degraded-mode duration,
  actions affected count, recovery trigger, proof pipeline health at recovery.
- `VEF-DEGRADE-ERR-001`: Transition failure — unexpected state or metric error.

## Recovery Receipts

When the system transitions back from a degraded mode to a less-degraded mode
or to normal, a recovery receipt is emitted containing:

- `degraded_mode_duration_secs`: How long the system was in the degraded tier.
- `actions_affected`: Count of actions that were blocked or annotated.
- `recovery_trigger`: Which metric(s) returned to healthy.
- `pipeline_health_at_recovery`: Snapshot of all proof lag metrics at recovery time.

## Configuration

All SLO thresholds and tier behavior are policy-configurable without code changes
via `VefDegradedModeConfig`:

```rust
pub struct VefDegradedModeConfig {
    pub restricted_slo: ProofLagSlo,
    pub quarantine_slo: ProofLagSlo,
    pub halt_multiplier: f64,            // default 2.0
    pub halt_error_rate: f64,            // default 0.50
    pub halt_heartbeat_timeout_secs: u64, // default 60
    pub stabilization_window_secs: u64,  // default 120
}
```

## Invariants

- **INV-VEF-DM-DETERMINISTIC**: Identical metric sequences always produce
  identical mode transition traces.
- **INV-VEF-DM-AUDIT**: Every mode transition emits an audit event; no
  silent transitions.
- **INV-VEF-DM-ESCALATE-IMMEDIATE**: Escalation to a higher tier is immediate
  upon SLO breach.
- **INV-VEF-DM-DEESCALATE-STABILIZED**: De-escalation requires stabilization
  window to elapse with metrics continuously below threshold.
- **INV-VEF-DM-RECOVERY-RECEIPT**: Every de-escalation produces a recovery
  receipt with required fields.

## Acceptance Criteria

1. Mode transitions are deterministic: identical metric sequences always
   trigger identical transitions.
2. SLO thresholds are configurable per policy tier and action class.
3. Audit events include: current mode, target mode, triggering metric,
   metric value, SLO threshold, timestamp, correlation ID.
4. Recovery receipts include: degraded-mode duration, actions affected,
   recovery trigger, proof pipeline health at recovery.
5. No silent mode transitions.
6. Mode enforcement is consistent across all VEF-gated control points.
