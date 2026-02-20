# Canonical Evidence-Artifact Namespace Contract

**Owner bead:** bd-2twu
**Policy version:** 1.0

## Purpose

Every bead produces deterministic, non-colliding, machine-indexable evidence artifacts.
This contract defines the naming schema, mandatory metadata, and collision detection rules
so downstream verification gates can consume artifacts without ambiguity.

## Artifact Path Schema

All evidence artifacts follow this canonical path pattern:

```
artifacts/{scope}/{section}/{artifact_type}/{bead_id}_{scenario_id}.json
```

### Path components

| Component | Description | Example |
|---|---|---|
| `scope` | `section`, `program`, `bootstrap`, or `oracle` | `section` |
| `section` | Plan section number (e.g., `10.13`, `11`, `bootstrap`) | `10.14` |
| `artifact_type` | One of the canonical types below | `unit_test` |
| `bead_id` | Owning bead identifier | `bd-xyz1` |
| `scenario_id` | Deterministic scenario identifier | `happy_path` |

### Canonical artifact types

| Type | Description | Extension |
|---|---|---|
| `unit_test` | Unit test results | `.json` |
| `integration_test` | Integration test results | `.json` |
| `e2e_test` | End-to-end test results | `.json` |
| `benchmark` | Benchmark results | `.json` |
| `coverage` | Code coverage report | `.json` |
| `lint` | Linter output | `.json` |
| `gate_verdict` | Verification gate verdict | `.json` |
| `provenance` | Execution provenance (rch) | `.json` |
| `drift_report` | Drift detection report | `.json` |
| `manifest` | Artifact manifest index | `.json` |

### Examples

```
artifacts/section/10.14/unit_test/bd-abc1_epoch_transition.json
artifacts/section/10.13/e2e_test/bd-def2_trust_chain_verify.json
artifacts/program/program/gate_verdict/bd-2j9w_program_gate.json
artifacts/oracle/oracle/gate_verdict/l1_product_verdict.json
artifacts/bootstrap/bootstrap/manifest/bd-jvzc_test_matrix.json
```

## Mandatory Manifest Metadata

Every artifact MUST include these metadata fields in its top-level JSON:

```json
{
  "artifact_meta": {
    "schema_version": "1.0",
    "bead_id": "bd-xyz1",
    "section": "10.14",
    "artifact_type": "unit_test",
    "scenario_id": "epoch_transition_happy",
    "seed": 42,
    "profile": "default",
    "timestamp": "2026-02-20T08:00:00Z",
    "commit": "abc123def",
    "trace_id": "trace-550e8400-e29b-41d4"
  }
}
```

| Field | Required | Description |
|---|---|---|
| `schema_version` | yes | Artifact namespace schema version |
| `bead_id` | yes | Owning bead that produced this artifact |
| `section` | yes | Plan section the artifact belongs to |
| `artifact_type` | yes | One of the canonical types |
| `scenario_id` | yes | Deterministic scenario identifier |
| `seed` | no | Random seed if applicable (for deterministic replay) |
| `profile` | no | Build/test profile used |
| `timestamp` | yes | ISO 8601 UTC production time |
| `commit` | yes | Git commit hash at production time |
| `trace_id` | yes | Distributed trace ID for correlation |

## Collision Detection Rules

1. **Path uniqueness:** No two artifacts may resolve to the same canonical path.
2. **Detection:** `scripts/verify_artifact_namespace.py` scans the artifacts tree and flags collisions.
3. **Enforcement:** Collision detection runs in all section and program verification gates.
4. **Resolution:** If a collision is detected, the producing bead must disambiguate by adjusting `scenario_id`.

## Migration from Legacy Paths

Existing artifacts (e.g., `artifacts/oracle/l1_product_verdict.json`) retain their paths
under a compatibility mapping in `scripts/verify_artifact_namespace.py`. New artifacts
MUST use the canonical schema. Legacy paths will be migrated to canonical form when their
owning beads are next updated.

## Gate Integration

All verification gates consume the artifact namespace validation report as a required input.
A FAIL verdict blocks the gate from passing. The report is produced by:

```bash
python3 scripts/verify_artifact_namespace.py --json
```
