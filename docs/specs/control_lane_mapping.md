# Control-Plane Lane Mapping Policy (bd-cuut)

**Section:** 10.15 — Asupersync-First Integration
**Upstream:** bd-qlc6 (10.14 — Canonical scheduler lane infrastructure)
**Status:** Active

## Purpose

Maps every control-plane task class to a scheduler lane with explicit priority,
budget, and starvation thresholds. Builds on the four-lane scheduler from
Section 10.14.

## Lane Classes

The four canonical scheduler lanes defined in `10.14/bd-qlc6` are mapped to
three control-plane workload tiers:

| Control Tier | Scheduler Lane    | Priority Weight | Concurrency Cap | Starvation Window |
|--------------|-------------------|-----------------|-----------------|-------------------|
| **Cancel**   | ControlCritical   | 100             | 8               | 1000 ms           |
| **Timed**    | RemoteEffect      | 50              | 32              | 3000 ms           |
| **Ready**    | Maintenance + Background | 20 / 10  | 4 / 2           | 5000 ms           |

### Cancel Tier (ControlCritical lane)

Cancellation handlers, drain operations, region close, and emergency barriers.
Highest priority. Guaranteed minimum budget of **20%** of scheduler capacity.
Starvation detection at **1000 ms** — a Cancel-tier task must never wait more
than 1 tick (≈1 starvation window).

**Task classes:**
- `epoch_transition` — monotonic control epoch advancement
- `barrier_coordination` — cross-service drain/quiescence barriers
- `marker_write` — append-only marker stream writes

### Timed Tier (RemoteEffect lane)

Health checks, lease renewals, remote computations, artifact lifecycle
transitions. Deadline-bound with timeout enforcement. Guaranteed minimum budget
of **30%** of scheduler capacity.

**Task classes:**
- `remote_computation` — outbound trust/control RPCs
- `artifact_upload` — L2→L3 lifecycle transitions
- `artifact_eviction` — eviction saga phases

### Ready Tier (Maintenance + Background lanes)

Background maintenance, telemetry flush, evidence archival. Best-effort with a
starvation floor — Ready-tier tasks always receive at least **10%** of scheduler
capacity even under Cancel/Timed pressure.

**Task classes (Maintenance lane):**
- `garbage_collection` — orphan artifact cleanup
- `compaction` — storage compaction passes

**Task classes (Background lane):**
- `telemetry_export` — structured telemetry export
- `log_rotation` — audit log rotation and archival

## Budget Allocations

| Tier     | Minimum Budget | Notes                                  |
|----------|---------------|----------------------------------------|
| Cancel   | 20%           | Guaranteed even under full load         |
| Timed    | 30%           | Deadline enforcement on each task       |
| Ready    | 10%           | Starvation floor prevents total starve  |
| Unallocated | 40%       | Distributed proportionally by weight    |

Budget enforcement is **proportional to priority weight** for the unallocated
portion: Cancel gets 100/(100+50+20+10) = ~56% of the remaining 40%, Timed
gets ~28%, Maintenance gets ~11%, Background gets ~5%.

## Starvation Detection Thresholds

| Lane            | Max Zero-Slot Ticks | Alert Code        |
|-----------------|---------------------|--------------------|
| ControlCritical | 1                   | LANE_STARVED       |
| RemoteEffect    | 3                   | LANE_STARVED       |
| Maintenance     | 5                   | LANE_STARVED       |
| Background      | 5                   | LANE_STARVED       |

A "tick" is defined as one scheduling cycle. If a lane receives zero scheduling
slots for more than the threshold number of consecutive ticks, a starvation
alert is emitted via event code `LANE_STARVED` with the lane identifier, queue
depth, and elapsed milliseconds.

## Invariants

- **INV-CLP-CANCEL-NEVER-STARVED**: Cancel-tier tasks are never starved for
  more than 1 tick. If Cancel tasks are pending and Timed/Ready tasks are being
  scheduled, the scheduler must preempt in favour of Cancel.
- **INV-CLP-BUDGET-SUM**: Minimum budget allocations sum to ≤ 100%.
  (20 + 30 + 10 = 60%, leaving 40% unallocated.)
- **INV-CLP-EVERY-CLASS-MAPPED**: Every task class in the control-plane module
  has a lane assignment. No unclassified tasks reach the scheduler.
- **INV-CLP-CANCEL-BEFORE-READY**: When both Cancel and Ready tasks are pending,
  Cancel tasks are scheduled first (enforced by priority weight ordering).

## Event Codes

All events use the existing `LANE_*` event code namespace from `10.14/bd-qlc6`:

| Code                     | Meaning                                 |
|--------------------------|-----------------------------------------|
| `LANE_ASSIGN`            | Task assigned to lane                   |
| `LANE_STARVED`           | Starvation detected in lane             |
| `LANE_STARVATION_CLEARED`| Starvation resolved after recovery      |
| `LANE_CAP_REACHED`       | Concurrency cap hit, task queued        |
| `LANE_TASK_STARTED`      | Task execution began                    |
| `LANE_TASK_COMPLETED`    | Task execution completed                |
| `LANE_POLICY_RELOADED`   | Lane policy hot-reloaded                |

## Conformance Requirements

1. Every task class in the well-known set has a lane assignment in the default
   policy.
2. Budget allocations (minimum budgets) sum to ≤ 100%.
3. Cancel-lane tasks are always scheduled before Ready-lane tasks when both are
   pending (priority weight ordering).
4. Starvation simulation: flood Ready lane, assert Cancel-lane tasks still
   execute within their budget.
5. Starvation metrics CSV is generated with per-tick lane counters.
