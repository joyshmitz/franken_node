# bd-3u6o: Enforce Canonical Virtual Transport Fault Harness for Distributed Control Protocols

## Summary

Adopts and enforces the virtual transport fault harness (bd-2qqu, Section 10.14)
for all distributed control protocols in franken_node. Every protocol that
exchanges messages between nodes must be exercised under deterministic fault
injection using the canonical `VirtualTransportFaultHarness`. No protocol may
use a custom or ad-hoc fault harness.

## Section

10.15 --- Control-Protocol Integration & Adoption

## Schema Version

tfg-v1.0

## Type

Adoption / Integration bead (enforces upstream bd-2qqu on control protocols)

## Upstream Dependencies

- **bd-2qqu** (10.14): Virtual Transport Fault Harness ---
  `crates/franken-node/src/remote/virtual_transport_faults.rs`
- **bd-145n** (10.15): Deterministic Lab Scenarios (seed matrix model)

## Implementation

- **Module**: `crates/franken-node/src/connector/transport_fault_gate.rs`
- **Wired in**: `crates/franken-node/src/connector/mod.rs`

## Protocols Under Test

| Protocol | Enum Variant | Fault Response |
|----------|-------------|----------------|
| Epoch Transition | `ControlProtocol::EpochTransition` | Retry vote, abort |
| Lease Renewal | `ControlProtocol::LeaseRenewal` | Retry, fail-closed |
| Evidence Commit | `ControlProtocol::EvidenceCommit` | Retry, compensate |
| Marker Append | `ControlProtocol::MarkerAppend` | Retry, abort |
| Fencing Acquire | `ControlProtocol::FencingAcquire` | Retry, fail-closed |
| Health Check | `ControlProtocol::HealthCheck` | Retry, degrade |

## Fault Classes

- **DROP**: Silent message discard (`FaultMode::Drop`)
- **REORDER**: Out-of-order delivery (`FaultMode::Reorder`)
- **CORRUPT**: Bit-level payload corruption (`FaultMode::Corrupt`)
- **PARTITION**: Bidirectional communication blackout (`FaultMode::Partition`)
- **NONE**: Baseline (no faults) (`FaultMode::None`)

## Event Codes

| Code | Meaning |
|------|---------|
| TFG-001 | Fault harness started for a control protocol |
| TFG-002 | Fault injected (drop/reorder/corrupt/partition) |
| TFG-003 | Protocol completed correctly under fault |
| TFG-004 | Protocol failed correctly (deterministic failure) |
| TFG-005 | Protocol produced incorrect result -- gate failure |
| TFG-006 | Full gate evaluation started |
| TFG-007 | Full gate evaluation completed |
| TFG-008 | Seed stability check completed |

## Error Codes

| Code | Meaning |
|------|---------|
| ERR_TFG_INVALID_CONFIG | Invalid fault configuration supplied to gate |
| ERR_TFG_UNKNOWN_PROTOCOL | Protocol not registered in the gate |
| ERR_TFG_SEED_UNSTABLE | Seed stability assertion failed |
| ERR_TFG_GATE_FAILED | Gate verdict: at least one protocol failed incorrectly |
| ERR_TFG_PARTITION_ERROR | Partition simulation error |
| ERR_TFG_INIT_FAILED | Harness initialization failed |

## Invariants

- **INV-VTF-DETERMINISTIC** (alias INV-TFG-DETERMINISTIC): Same seed and protocol produce identical fault sequences and outcomes
- **INV-VTF-CORRECT-OR-FAIL** (alias INV-TFG-CORRECT-OR-FAIL): Protocols either succeed correctly or fail closed; no silent corruption
- **INV-VTF-NO-CUSTOM** (alias INV-TFG-NO-CUSTOM): All protocols must use the canonical harness; no ad-hoc fault injection
- **INV-VTF-SEED-STABLE** (alias INV-TFG-SEED-STABLE): Seed-to-schedule mapping is stable across code versions
- **INV-TFG-FULL-COVERAGE**: Gate must test every registered protocol under every fault mode
- **INV-TFG-PARTITION-CLOSED**: Partition faults cause fail-closed behavior

## Acceptance Criteria

1. Integration module exists at `crates/franken-node/src/connector/transport_fault_gate.rs`
   and is wired in `connector/mod.rs`.
2. Module imports and wraps the canonical bd-2qqu harness from
   `crate::remote::virtual_transport_faults` -- no custom fault injection.
3. Six control-plane protocols are registered as fault injection targets.
4. `TransportFaultGate::run_full_gate()` exercises every protocol under each fault mode
   with the default seed matrix (5 seeds).
5. All six invariants (INV-TFG-*) are documented in both the spec and the implementation.
6. At least 18 inline `#[test]` functions exist in the module.
7. Gate script `scripts/check_transport_fault_gate.py` passes all checks.
8. Unit tests in `tests/test_check_transport_fault_gate.py` pass.

## Test Scenarios

- **Scenario 1 --- Full matrix pass**: All protocol x fault-mode x seed combinations
  produce acceptable (correct-or-fail) outcomes.
- **Scenario 2 --- Seed stability**: Re-running seed 42 on epoch_transition produces
  identical content hashes.
- **Scenario 3 --- No custom harness**: Module uses `use crate::remote::virtual_transport_faults`.
- **Scenario 4 --- Partition handling**: All six protocols fail closed under partition.

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_15/bd-3u6o_contract.md` |
| Testing doc | `docs/testing/control_virtual_transport_faults.md` |
| Rust tests | `tests/harness/control_virtual_transport_faults.rs` |
| Report | `artifacts/10.15/control_fault_harness_summary.json` |
| Gate script | `scripts/check_control_transport_faults.py` |
| Unit tests | `tests/test_check_control_transport_faults.py` |
| Evidence | `artifacts/section_10_15/bd-3u6o/verification_evidence.json` |
| Summary | `artifacts/section_10_15/bd-3u6o/verification_summary.md` |
