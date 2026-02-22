# bd-10g0: Section 10.16 Verification Gate Contract

**Schema**: gate-v1.0
**Section**: 10.16 — Adjacent Substrate Integration
**Type**: Section-wide verification gate

## Purpose

Aggregates verification evidence from all 17 Section 10.16 beads and validates
that the adjacent substrate integration is complete across all four planes:
frankentui (presentation), frankensqlite (persistence), sqlmodel_rust (model),
and fastapi_rust (service).

## Upstream Beads

| Bead | Domain | Description |
|------|--------|-------------|
| bd-2owx | Policy | Substrate policy contract |
| bd-28ld | Architecture | Dependency map |
| bd-34ll | frankentui | Integration contract |
| bd-1xtf | frankentui | TUI workflow migration |
| bd-1719 | frankentui | Visual/snapshot tests |
| bd-1a1j | frankensqlite | Persistence contract |
| bd-2tua | frankensqlite | Adapter layer |
| bd-26ux | frankensqlite | Migration path |
| bd-bt82 | sqlmodel_rust | Usage policy |
| bd-1v65 | sqlmodel_rust | Integration |
| bd-3ndj | fastapi_rust | Service contract |
| bd-2f5l | fastapi_rust | Service skeleton |
| bd-159q | Governance | Waiver workflow |
| bd-2ji2 | Governance | Claim-language gate |
| bd-35l5 | Performance | Overhead guardrails |
| bd-3u2o | CI | Conformance gate |
| bd-8l9k | E2E | Cross-substrate tests |

## Invariants

| ID | Description |
|----|-------------|
| INV-GATE-16-ALL-EVIDENCE | All 17 beads have verification evidence |
| INV-GATE-16-ALL-PASS | All 17 beads have PASS verdict |
| INV-GATE-16-ALL-SUMMARIES | All 17 beads have verification summaries |
| INV-GATE-16-SUBSTRATE-COVERAGE | All 4 substrates have passing beads |
| INV-GATE-16-DETERMINISTIC | Gate verdict is pure function of evidence |

## Acceptance Criteria

1. Evidence exists for all 17 section beads.
2. All evidence has PASS verdict.
3. Summaries exist for all beads.
4. All four substrate planes have full coverage.
5. Gate script produces deterministic, machine-readable output.
6. Gate spec, evidence, summary, and test file exist.
7. Section-level test matrix artifact classifies happy-path, edge-case, and adversarial/error scenarios.
8. Structured logging traceability bundle includes stable event/error codes and trace-correlation evidence.
9. Release-consumable gate verdict artifact is present and machine-readable.

## Artifacts

| Artifact | Path |
|----------|------|
| Gate script | `scripts/check_section_10_16_gate.py` |
| Gate tests | `tests/test_check_section_10_16_gate.py` |
| Gate evidence | `artifacts/section_10_16/bd-10g0/verification_evidence.json` |
| Gate summary | `artifacts/section_10_16/bd-10g0/verification_summary.md` |
| Gate spec | `docs/specs/section_10_16/bd-10g0_contract.md` |
| Section test matrix | `artifacts/10.16/section_10_16_test_matrix.json` |
| Traceability bundle | `artifacts/10.16/section_10_16_traceability_bundle.json` |
| Release gate verdict | `artifacts/10.16/section_10_16_gate_verdict.json` |
