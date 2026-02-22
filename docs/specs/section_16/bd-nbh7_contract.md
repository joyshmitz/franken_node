# bd-nbh7: Benchmark/Verifier Methodology Publications — Spec Contract

**Section:** 16 — Contribution: Open Datasets & Tooling
**Bead:** bd-nbh7
**Status:** CLOSED

## Purpose

Publish methodology documentation for benchmark design and verifier
architecture with structured sections, citations, reproducibility checklists,
and peer-review status tracking.

## Acceptance Criteria

1. Five methodology topics: BenchmarkDesign, VerifierArchitecture,
   MetricDefinition, ReproducibilityProtocol, ThreatModeling.
2. Four publication statuses: Draft → Review → Published → Archived.
3. Six required methodology sections per publication (INV-BMP-STRUCTURED).
4. Same inputs produce same catalog output (INV-BMP-DETERMINISTIC).
5. Every publication has unique identifier (INV-BMP-CITABLE).
6. Every publication includes reproducibility checklist (INV-BMP-REPRODUCIBLE).
7. Publication version embedded in every artifact (INV-BMP-VERSIONED).
8. Every state change produces audit record (INV-BMP-AUDITABLE).
9. At least 12 event codes (BMP-001 through BMP-ERR-002).
10. At least 22 Rust unit tests.

## Invariants

| ID | Description |
|---|---|
| INV-BMP-STRUCTURED | Every publication has required methodology sections |
| INV-BMP-DETERMINISTIC | Same inputs produce same catalog output |
| INV-BMP-CITABLE | Every publication has unique DOI-style identifier |
| INV-BMP-REPRODUCIBLE | Every publication includes reproducibility checklist |
| INV-BMP-VERSIONED | Publication version embedded in every artifact |
| INV-BMP-AUDITABLE | Every state change produces audit record |

## Implementation

| Artifact | Path |
|---|---|
| Rust module | `crates/franken-node/src/tools/benchmark_methodology.rs` |
| Module wiring | `crates/franken-node/src/tools/mod.rs` |
| Verification script | `scripts/check_benchmark_methodology.py` |
| Unit tests | `tests/test_check_benchmark_methodology.py` |
