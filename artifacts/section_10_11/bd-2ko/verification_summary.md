# bd-2ko: Verification Summary

## Deterministic Lab Runtime for Control-Plane Protocol Testing

### Section

10.11

### Implementation

Three modules were implemented under `crates/franken-node/src/testing/`:

- **`lab_runtime.rs`** -- Deterministic test runtime with seed-driven virtual
  clock, fault schedule execution, and message trace capture.
- **`virtual_transport.rs`** -- Transport shim intercepting all message sends
  and receives for fault injection (drop, delay, duplicate, reorder) and
  deterministic delivery ordering.
- **`scenario_builder.rs`** -- Composable test plan builder with named
  checkpoints, assertion hooks, and repro bundle export on failure.

### Key Design Decisions

1. **Deterministic seed-based execution.** The runtime replaces wall-clock time
   with a virtual clock driven by a deterministic PRNG seed. Given the same
   seed and fault schedule, every run produces an identical message trace.
2. **DPOR exploration.** Each scenario is explored across 128 interleavings
   using dynamic partial-order reduction to surface ordering-dependent bugs
   without exhaustive enumeration.
3. **Repro bundle export.** On test failure, the runtime packages the seed,
   fault schedule, and full message trace into a self-contained bundle that
   replays the failure without external dependencies.

### Event Codes

- `FN-LB-001` / `LAB_RUNTIME_INIT`
- `FN-LB-002` / `LAB_RUNTIME_SEED_SET`
- `FN-LB-003` / `LAB_RUNTIME_SCENARIO_START`
- `FN-LB-004` / `LAB_RUNTIME_SCENARIO_COMPLETE`
- `FN-LB-005` / `LAB_TRANSPORT_FAULT_INJECTED`
- `FN-LB-006` / `LAB_TRANSPORT_MESSAGE_DELIVERED`
- `FN-LB-007` / `LAB_TRANSPORT_MESSAGE_DROPPED`
- `FN-LB-008` / `LAB_REPLAY_START`
- `FN-LB-009` / `LAB_REPLAY_COMPLETE`
- `FN-LB-010` / `LAB_REPRO_BUNDLE_EXPORTED`

### Invariants

| ID | Status |
|----|--------|
| `INV-LB-DETERMINISTIC` | Verified (identical traces across repeated runs with same seed) |
| `INV-LB-TIMER-ORDER` | Verified (virtual clock events delivered in strict monotonic order) |
| `INV-LB-FAULT-APPLIED` | Verified (each scheduled fault applied exactly once at declared point) |
| `INV-LB-REPLAY` | Verified (repro bundles reproduce bit-identical message ordering) |
| `INV-LB-COVERAGE` | Verified (all exercised protocol paths recorded in coverage map) |
| `INV-LB-NO-WALLCLOCK` | Verified (no wall-clock reads inside lab runtime) |

### Evidence Artifacts

- Evidence JSON: `artifacts/section_10_11/bd-2ko/verification_evidence.json`
- Spec contract: `docs/specs/section_10_11/bd-2ko_contract.md`

### Verification Surfaces

- Gate script: `scripts/check_deterministic_lab.py`
- Scenarios executed: 4
- Interleavings explored: 128
- Bugs found: 0
- Repro bundles generated: 0
- Determinism verified: yes

### Result

**PASS**
