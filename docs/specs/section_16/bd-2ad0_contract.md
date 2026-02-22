# bd-2ad0: Reproducible Migration and Incident Datasets — Spec Contract

**Section:** 16 — Contribution: Open Datasets & Tooling
**Bead:** bd-2ad0
**Status:** CLOSED

## Purpose

Publish reproducible, versioned datasets for migration scenarios and security
incidents so external researchers can independently verify and reproduce
franken_node results.

## Acceptance Criteria

1. Five dataset types: MigrationScenario, SecurityIncident, BenchmarkBaseline,
   CompatibilityMatrix, TrustEvidence.
2. Every dataset entry carries SHA-256 content hash (INV-RDS-INTEGRITY).
3. Every dataset includes provenance metadata linking to source bead and build
   context (INV-RDS-PROVENANCE).
4. Every dataset includes deterministic replay instructions with at least one
   command (INV-RDS-REPRODUCIBLE).
5. Schema version embedded in every bundle (INV-RDS-VERSIONED).
6. Datasets below configured record threshold are rejected (INV-RDS-GATED).
7. Same inputs produce same catalog output (INV-RDS-DETERMINISTIC).
8. Bundle publication aggregates records and produces integrity hash.
9. Catalog generation groups datasets by type with total counts.
10. Audit log with JSONL export for every mutation event.
11. At least 12 event codes defined (RDS-001 through RDS-ERR-002).
12. At least 22 Rust unit tests covering registration, bundling, catalog, audit.

## Invariants

| ID | Description |
|---|---|
| INV-RDS-INTEGRITY | Every dataset has a SHA-256 content hash |
| INV-RDS-DETERMINISTIC | Same dataset inputs produce same catalog output |
| INV-RDS-PROVENANCE | Every dataset links to source bead and build context |
| INV-RDS-REPRODUCIBLE | Every dataset includes replay instructions |
| INV-RDS-VERSIONED | Schema version embedded in every bundle |
| INV-RDS-GATED | Datasets below completeness threshold blocked |

## Event Codes

| Code | Description |
|---|---|
| RDS-001 | Dataset registered |
| RDS-002 | Integrity hash verified |
| RDS-003 | Provenance metadata attached |
| RDS-004 | Replay instructions validated |
| RDS-005 | Bundle published |
| RDS-006 | Catalog generated |
| RDS-007 | Schema version verified |
| RDS-008 | Completeness check passed |
| RDS-009 | Report generated |
| RDS-010 | Version recorded |
| RDS-ERR-001 | Integrity hash invalid |
| RDS-ERR-002 | Dataset below completeness threshold |

## Implementation

| Artifact | Path |
|---|---|
| Rust module | `crates/franken-node/src/tools/migration_incident_datasets.rs` |
| Module wiring | `crates/franken-node/src/tools/mod.rs` |
| Verification script | `scripts/check_reproducible_datasets.py` |
| Unit tests | `tests/test_check_reproducible_datasets.py` |
