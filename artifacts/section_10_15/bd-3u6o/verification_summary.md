# bd-3u6o: Transport Fault Gate -- Verification Summary

**Section:** 10.15 | **Bead:** bd-3u6o | **Schema:** tfg-v1.0 | **Date:** 2026-02-21

## Gate Result: PASS

| Metric | Value |
|--------|-------|
| Check script checks | 66/66 PASS |
| Self-test checks | 15/15 PASS |
| Python test suite | 19/19 PASS |
| Rust inline tests | 28 |
| Protocols registered | 6 |
| Fault modes | 5 (NONE, DROP, REORDER, CORRUPT, PARTITION) |
| Default seeds | 5 (42, 137, 256, 1001, 9999) |
| Event codes | 8 (TFG-001 through TFG-008) |
| Error codes | 6 (ERR_TFG_*) |
| Invariants | 6 (INV-TFG-*) |

## Key Capabilities

- Wraps canonical `VirtualTransportFaultHarness` from bd-2qqu (Section 10.14)
- Imports via `use crate::remote::virtual_transport_faults` -- no custom fault injection
- Six control-plane protocols registered as fault injection targets:
  epoch_transition, lease_renewal, evidence_commit, marker_append,
  fencing_acquire, health_check
- `TransportFaultGate::run_full_gate()` exercises every protocol under each fault mode
- Seed stability verified: same seed produces identical content hashes
- Partition modeled as 100% drop (bidirectional blackout)
- All protocols fail closed under partition (INV-TFG-PARTITION-CLOSED)

## Invariants Verified

- **INV-TFG-DETERMINISTIC**: Same seed and protocol produce identical results across runs
- **INV-TFG-CORRECT-OR-FAIL**: All protocols either succeed or fail closed; no silent corruption
- **INV-TFG-NO-CUSTOM**: All protocols use the shared canonical harness from bd-2qqu
- **INV-TFG-SEED-STABLE**: Seed-to-schedule mapping stable across code versions
- **INV-TFG-FULL-COVERAGE**: Gate tests every protocol under every fault mode
- **INV-TFG-PARTITION-CLOSED**: Partition faults always cause fail-closed behavior

## Deliverables

| Artifact | Path | Status |
|----------|------|--------|
| Implementation | `crates/franken-node/src/connector/transport_fault_gate.rs` | 28 inline tests |
| Wired in | `crates/franken-node/src/connector/mod.rs` | `pub mod transport_fault_gate` |
| Spec contract | `docs/specs/section_10_15/bd-3u6o_contract.md` | Complete |
| Check script | `scripts/check_transport_fault_gate.py` | 66/66 PASS |
| Test suite | `tests/test_check_transport_fault_gate.py` | 19/19 PASS |
| Evidence | `artifacts/section_10_15/bd-3u6o/verification_evidence.json` | PASS |
| Summary | `artifacts/section_10_15/bd-3u6o/verification_summary.md` | This file |
