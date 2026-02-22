# bd-n1w Contract: Frontier Demo Gates with External Reproducibility

**Bead:** bd-n1w
**Section:** 10.12 (Ecosystem Fabric + Network Effects)
**Status:** Active
**Owner:** CrimsonCrane
**Schema:** gate-v1.0

## Overview

Shared demo-gate infrastructure for all five frontier programs (Migration
Singularity, Trust Fabric, Verifier Economy, Operator Intelligence, Ecosystem
Network Effects).  Ensures external reproducibility as a hard requirement by
producing manifests, a demo-gate runner, and external-verifier bootstrap
artefacts.

## Data Model

### FrontierProgram (enum)

| Variant                    | Description                        |
|----------------------------|------------------------------------|
| `MigrationSingularity`     | Migration singularity program      |
| `TrustFabric`              | Trust fabric program               |
| `VerifierEconomy`          | Verifier economy program           |
| `OperatorIntelligence`     | Operator intelligence program      |
| `EcosystemNetworkEffects`  | Ecosystem network effects program  |

### DemoGateResult

| Field               | Type              | Description                         |
|---------------------|-------------------|-------------------------------------|
| `program`           | `FrontierProgram` | Which frontier program ran          |
| `passed`            | `bool`            | Whether the gate passed             |
| `timing_ms`         | `u64`             | Execution time in milliseconds      |
| `resource_metrics`  | `ResourceMetrics` | CPU, memory, I/O metrics            |
| `output_fingerprint`| `String`          | SHA-256 of gate output              |
| `schema_version`    | `String`          | Schema version (`demo-v1.0`)        |
| `detail`            | `String`          | Human-readable detail string        |

### ResourceMetrics

| Field               | Type   | Description                 |
|---------------------|--------|-----------------------------|
| `peak_memory_bytes` | `u64`  | Peak memory during gate     |
| `cpu_time_ms`       | `u64`  | CPU time in ms              |
| `io_operations`     | `u64`  | Number of I/O operations    |

### ReproducibilityManifest

| Field                  | Type                       | Description                            |
|------------------------|----------------------------|----------------------------------------|
| `schema_version`       | `String`                   | Schema version (`demo-v1.0`)           |
| `git_commit_hash`      | `String`                   | Git commit hash at execution time      |
| `input_fingerprints`   | `BTreeMap<String, String>` | SHA-256 fingerprints of gate inputs    |
| `output_fingerprints`  | `BTreeMap<String, String>` | SHA-256 fingerprints of gate outputs   |
| `environment_metadata` | `BTreeMap<String, String>` | OS, arch, Rust version, etc.           |
| `timing_per_gate`      | `BTreeMap<String, u64>`    | Execution time per gate                |
| `manifest_fingerprint` | `String`                   | SHA-256 over canonical manifest JSON   |

### ExternalVerifierBootstrap

| Field                        | Type                       | Description                          |
|------------------------------|----------------------------|--------------------------------------|
| `schema_version`             | `String`                   | Schema version (`demo-v1.0`)         |
| `manifest`                   | `ReproducibilityManifest`  | The manifest to reproduce            |
| `gate_results`               | `Vec<DemoGateResult>`      | Results to verify against            |
| `verification_instructions`  | `String`                   | Step-by-step re-execution guide      |
| `expected_output_hash`       | `String`                   | SHA-256 of serialised results        |

### DemoGateRunner

| Field                 | Type                     | Description                      |
|-----------------------|--------------------------|----------------------------------|
| `schema_version`      | `String`                 | Schema version                   |
| `registered_programs` | `Vec<FrontierProgram>`   | Registered frontier programs     |
| `results`             | `Vec<DemoGateResult>`    | Collected results                |
| `events`              | `Vec<DemoEvent>`         | Emitted events                   |

## Trait: FrontierDemoGate

```rust
pub trait FrontierDemoGate {
    fn input_corpus(&self) -> BTreeMap<String, String>;
    fn execute(&self) -> DemoGateResult;
    fn output_schema(&self) -> String;
    fn attestation(&self) -> String;
}
```

## Invariants

- **INV-DEMO-DETERMINISTIC** -- Same inputs always produce the same outputs and fingerprints.
- **INV-DEMO-ISOLATED** -- Each gate executes in an isolated context with no shared mutable state.
- **INV-DEMO-FINGERPRINTED** -- Every input and output carries a SHA-256 fingerprint.
- **INV-DEMO-REPRODUCIBLE** -- External re-execution must yield byte-for-byte matching outputs.
- **INV-DEMO-MANIFEST-COMPLETE** -- Manifest includes git hash, timing, environment metadata.
- **INV-DEMO-SCHEMA-VERSIONED** -- All serialised artefacts carry the schema version string.

## Event Codes

| Code     | Severity | Description                              |
|----------|----------|------------------------------------------|
| DEMO-001 | INFO     | Demo gate execution started              |
| DEMO-002 | INFO     | Demo gate passed                         |
| DEMO-003 | WARN     | Demo gate failed                         |
| DEMO-004 | INFO     | Reproducibility manifest generated       |
| DEMO-005 | INFO     | External verification started            |
| DEMO-006 | INFO     | External verification matched            |
| DEMO-007 | WARN     | External verification mismatch detected  |

## Error Codes

| Code                            | Description                                  |
|---------------------------------|----------------------------------------------|
| ERR_DEMO_GATE_NOT_FOUND         | Requested gate not found in registry         |
| ERR_DEMO_EXECUTION_FAILED       | Gate execution failed unexpectedly           |
| ERR_DEMO_FINGERPRINT_MISMATCH   | Input or output fingerprint does not match   |
| ERR_DEMO_MANIFEST_INVALID       | Manifest validation failed                   |
| ERR_DEMO_BOOTSTRAP_FAILED       | External verifier bootstrap creation failed  |
| ERR_DEMO_ISOLATION_VIOLATED     | Gate isolation invariant was violated         |
| ERR_DEMO_SCHEMA_MISMATCH        | Schema version mismatch detected             |

## Acceptance Criteria

1. Rust module at `crates/franken-node/src/tools/frontier_demo_gate.rs` with all types and trait.
2. `FrontierDemoGate` trait with `input_corpus`, `execute`, `output_schema`, `attestation`.
3. `DemoGateRunner` that discovers and executes registered frontier programs.
4. `ReproducibilityManifest` with git hash, fingerprints, environment, timing.
5. `FrontierProgram` enum with five variants.
6. `DemoGateResult` with pass/fail, timing, resource metrics.
7. `ExternalVerifierBootstrap` for re-execution and byte-for-byte diff.
8. Event codes DEMO-001 through DEMO-007 defined in `event_codes` module.
9. Error codes ERR_DEMO_* defined in `error_codes` module.
10. Invariants INV-DEMO-* (6) defined in `invariants` module.
11. Schema version `demo-v1.0` constant.
12. Serde derives on all public structs.
13. BTreeMap usage for deterministic ordering.
14. >= 40 unit tests.
15. Module wired into `tools/mod.rs`.
16. Demo manifest artifact at `artifacts/10.12/frontier_demo_manifest.json`.

## Artifacts

| Artifact                    | Path                                                              |
|-----------------------------|-------------------------------------------------------------------|
| Rust implementation         | `crates/franken-node/src/tools/frontier_demo_gate.rs`             |
| Demo manifest               | `artifacts/10.12/frontier_demo_manifest.json`                     |
| Spec contract               | `docs/specs/section_10_12/bd-n1w_contract.md`                     |
| Gate script                 | `scripts/check_frontier_demo_gates.py`                            |
| Test file                   | `tests/test_check_frontier_demo_gates.py`                         |
| Verification evidence       | `artifacts/section_10_12/bd-n1w/verification_evidence.json`       |
| Verification summary        | `artifacts/section_10_12/bd-n1w/verification_summary.md`          |
