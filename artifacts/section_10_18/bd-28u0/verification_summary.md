# bd-28u0 Verification Summary

**Bead:** bd-28u0
**Title:** VEF proof-window selection and job scheduler with bounded latency budgets
**Section:** 10.18
**Verdict:** PASS

## Implementation

The proof scheduler is implemented in `crates/franken-node/src/vef/proof_scheduler.rs` and wired into the VEF module via `src/vef/mod.rs`.

### Core Types

| Type | Purpose |
|------|---------|
| `VefProofScheduler` | Top-level scheduler managing windows and jobs |
| `SchedulerPolicy` | Configuration: window size, concurrency, compute/memory budgets, tier deadlines |
| `ProofWindow` | Bounded receipt window with checkpoint alignment |
| `ProofJob` | Scheduled proof job with tier, priority, deadline, resource estimates |
| `WorkloadTier` | Risk-tiered classification (Critical > High > Standard > Background) |
| `ProofJobStatus` | Job lifecycle: Pending -> Dispatched -> Completed / DeadlineExceeded |
| `SchedulerMetrics` | Backlog health: pending/dispatched/completed counts, budget usage, age |

### Contract Compliance

- **Deterministic window selection:** Identical receipt streams and policies produce identical window partitions (tested).
- **Priority ordering:** Critical-tier jobs dispatch before lower tiers using `Reverse(priority_score)` sort.
- **Deadline enforcement:** Jobs exceeding their tier-specific deadline are marked `DeadlineExceeded` with event `VEF-SCHED-ERR-001`.
- **Concurrency budget:** `dispatch_jobs` respects `max_concurrent_jobs` limit.
- **Resource budget:** Compute and memory estimates are checked against per-tick ceilings before dispatch.
- **Empty stream:** Returns empty window list without error.
- **Checkpoint alignment:** Windows align to receipt chain checkpoints when possible.
- **Event tracing:** All lifecycle transitions emit structured `SchedulerEvent` entries with trace IDs.

### Event Codes

| Code | Meaning |
|------|---------|
| VEF-SCHED-001 | Window selected |
| VEF-SCHED-002 | Job dispatched |
| VEF-SCHED-003 | Job completed |
| VEF-SCHED-004 | Backlog health report |
| VEF-SCHED-ERR-001 | Deadline exceeded |
| VEF-SCHED-ERR-002 | Budget exhausted |
| VEF-SCHED-ERR-003 | Window error |
| VEF-SCHED-ERR-004 | Internal error |

### Unit Tests (7)

1. `deterministic_window_partition_for_same_inputs` — same inputs yield same window bounds
2. `empty_stream_produces_no_windows` — empty receipt list returns empty windows
3. `enqueue_and_dispatch_respects_concurrency_budget` — concurrency limit enforced
4. `priority_prefers_critical_windows` — critical-tier jobs dispatch first
5. `deadline_enforcement_marks_jobs_as_exceeded` — expired jobs get DeadlineExceeded status
6. `backlog_metrics_report_pending_age` — metrics track oldest pending job age
7. `mark_completed_transitions_job` — completed jobs transition correctly

## Verification Artifacts

| Artifact | Path |
|----------|------|
| Check script | `scripts/check_vef_proof_scheduler.py` |
| Test suite | `tests/test_check_vef_proof_scheduler.py` |
| Evidence JSON | `artifacts/section_10_18/bd-28u0/verification_evidence.json` |
| Check report | `artifacts/section_10_18/bd-28u0/check_report.json` |
