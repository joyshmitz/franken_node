# bd-gad3 Verification Summary

- Status: **PASS**
- Checker: `scripts/check_isolation_mesh.py --json`
- Checker self-test: PASS
- Python unit tests: `tests/test_check_isolation_mesh.py`

## Delivered Surface

- `docs/specs/section_10_17/bd-gad3_contract.md`
- `crates/franken-node/src/runtime/isolation_mesh.rs`
- `scripts/check_isolation_mesh.py`
- `tests/test_check_isolation_mesh.py`
- `artifacts/section_10_17/bd-gad3/verification_evidence.json`
- `artifacts/section_10_17/bd-gad3/verification_summary.md`

## Acceptance Coverage

- Workloads can be promoted to stricter rails at runtime without losing policy continuity.
- Latency-sensitive trusted workloads remain on high-performance rails within budget (latency budget enforcement).
- Hot-elevation transitions are atomic: workload placement is updated in a single step with no intermediate state.
- Demotion from a stricter rail to a less strict rail is explicitly forbidden (fail-closed, MESH_007 event).
- Mesh topology is deterministic and auditable via BTreeMap ordering and structured events.
- Latency budget enforcement rejects elevation requests that would violate the budget (MESH_004 event).

## Key Design Decisions

- Four isolation levels ordered by strictness: Shared < ProcessIsolated < SandboxIsolated < HardwareIsolated.
- ElevationPolicy per workload controls whether elevation is permitted, max target level, and latency budget.
- 7 event codes (MESH_001..MESH_007) for full auditability.
- 8 error codes (ERR_MESH_*) for deterministic failure classification.
- 6 invariants (INV-MESH-*) documented in both spec contract and implementation.
- 24 inline Rust unit tests covering all invariants, error paths, and happy paths.
