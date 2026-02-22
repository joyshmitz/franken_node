# bd-2nt Verification Summary

## Bead: bd-2nt | Section: 10.11
## Title: VOI-Budgeted Monitor Scheduling

## Verdict: PASS (71/71 checks)

## Artifacts Delivered

| Artifact | Path | Status |
|----------|------|--------|
| Specification | `docs/specs/section_10_11/bd-2nt_contract.md` | Delivered |
| Rust module | `crates/franken-node/src/connector/diagnostic_registry.rs` | Delivered |
| Module registration | `crates/franken-node/src/connector/mod.rs` | Delivered |
| Verification script | `scripts/check_voi_scheduler.py` | Delivered |
| Unit tests | `tests/test_check_voi_scheduler.py` | Delivered |
| Evidence JSON | `artifacts/section_10_11/bd-2nt/verification_evidence.json` | Delivered |
| This summary | `artifacts/section_10_11/bd-2nt/verification_summary.md` | Delivered |

## Implementation Details

### Core Types

| Type | Description |
|------|-------------|
| `VoiConfig` | Budget, window, storm threshold, regime boost, VOI weights |
| `VoiScheduler` | Main scheduler with registry, state, storm detection |
| `DiagnosticDef` | Diagnostic definition: name, cost, wall_clock_ms, domains, staleness, priority |
| `DiagnosticState` | Per-diagnostic runtime: last_run_ts, historical_informativeness, uncertainty_level |
| `ScheduleDecision` | Per-diagnostic scheduling record |
| `ScheduleCycleResult` | Full cycle result with selected, deferred, preempted lists |
| `VoiEvent` | Event log entry |
| `VoiError` | Error enum with 5 variants |
| `PriorityClass` | Critical > Standard > Background |

### VOI Scoring (4 components)

- **Staleness** (weight 0.3): age / staleness_tolerance, capped at 1.0
- **Uncertainty** (weight 0.3): increases after regime shifts, decays after execution
- **Downstream impact** (weight 0.2): 1.0 if gates decisions, 0.3 otherwise
- **Historical informativeness** (weight 0.2): EWMA of actionable finding rate

### Methods (13 total)

- `VoiConfig::validate()` — Config validation (budget, weights sum to 1.0, etc.)
- `VoiScheduler::new()` — Create scheduler with validated config
- `register_diagnostic()` — Add diagnostic to registry
- `diagnostic_count()` — Count registered diagnostics
- `compute_voi()` — Compute VOI score for a diagnostic at given timestamp
- `schedule()` — Run full scheduling cycle with greedy selection
- `signal_regime_shift()` — Boost budget and increase uncertainty (from bd-3u4)
- `effective_budget()` — Current budget (base or boosted)
- `record_finding()` — Update EWMA of actionable findings
- `is_conservative()` — Whether storm mode is active
- `events()` — Get event log
- `diagnostic_names()` — List registered diagnostic names
- `get_diagnostic()` — Get diagnostic definition by name

### Default Diagnostics (12 total)

health_ping, trust_chain_validation, state_replay_verification, proof_generation_check, counter_read, retention_sweep, lease_audit, schema_drift_check, fencing_token_audit, telemetry_backlog_check, golden_vector_replay, crdt_convergence_check

### Invariants Enforced

- **INV-VOI-BUDGET**: Total cost in any cycle never exceeds effective budget
- **INV-VOI-ORDER**: Diagnostics selected in descending VOI/cost within priority class
- **INV-VOI-PREEMPT**: Critical diagnostics always selected before Standard/Background
- **INV-VOI-STORM**: Conservative mode activates at storm_threshold * budget for storm_windows consecutive cycles

### Rust Unit Tests (36 tests)

Coverage: config validation (valid, invalid budget/window/storm/weights), registration (success, duplicate, count, names, get), VOI scoring (positive, staleness, downstream, unknown), scheduling (basic, budget limits), invariant enforcement (budget, order, preemption, storm), storm protection (activation, conservative-only-critical), regime shift (boost, expiry, uncertainty increase), findings recording, empty registry error, error/priority display, priority ordering, events, default diagnostics (count, unique names, has critical, has all classes).

### Compilation

Binary target compiles via `rch exec -- cargo check --bin frankenengine-node` (exit 0).
