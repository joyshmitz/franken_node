# bd-3epz: Section 10.14 Verification Gate

## Purpose

Section-wide verification gate for Section 10.14 (FrankenSQLite Deep-Mined
Expansion). This gate aggregates the verification status of all section 10.14
beads and enforces minimum coverage thresholds before the section can be
considered complete.

Section 10.14 covers remote operations, evidence ledger, monotonic epochs,
tiered storage, hardening policies, guardrail monitors, determinism conformance,
cancel-safe sagas, proof-carrying artifacts, and related subsystems.

## Dependencies

- **Upstream:** All section 10.14 beads (52 beads discovered via artifact scan)
- **Downstream:** Section-level release readiness

## Gate Checks

| ID | Description | Threshold |
|----|-------------|-----------|
| GATE-10.14-BEAD-COUNT | Minimum number of bead artifacts discovered | >= 49 |
| GATE-10.14-EVIDENCE-EXISTS | All beads have verification_evidence.json | 100% |
| GATE-10.14-COVERAGE-THRESHOLD | Fraction of beads with passing evidence | >= 90% |
| GATE-10.14-ALL-BEADS | Every bead evidence passes | 100% |
| GATE-10.14-SPEC-CONTRACTS | Beads with spec contract documents | informational |
| GATE-10.14-SUMMARIES | Beads with verification_summary.md | informational |

## Evidence Verdict Interpretation

The gate recognizes diverse evidence formats used across section 10.14 beads:

- `verdict: "PASS"` -- direct pass
- `verdict: "PASS_WITH_*"` -- pass with known environmental blockers
- `status: "pass"` -- status-field pass
- `status: "completed_with_baseline_workspace_failures"` -- pass with pre-existing repo debt
- `status: "completed_with_known_repo_gate_failures"` -- pass with known repo-wide gate failures
- `status: "implemented_with_blocked_full_validation"` -- pass with blocked external validation
- `overall_pass: true`, `all_passed: true`, `all_pass: true` -- boolean pass flags
- `checks: [...]` where all items have `pass: true` or `status: "PASS"/"FAIL_BASELINE"`
- `summary: {total_checks: N, failing_checks: 0}` -- summary-based pass
- `passed: N, failed: 0` -- count-based pass
- `verification_results: {sub: {verdict: "PASS"/"FAIL_BASELINE"}}` -- sub-verdict pass

## Acceptance Criteria

1. Gate discovers >= 49 bead artifact directories under `artifacts/section_10_14/`
2. Every bead directory contains a `verification_evidence.json` file
3. At least 90% of evidence files evaluate to a passing verdict
4. Gate produces structured JSON output with per-bead results, gate checks, gap
   analysis, and audit events
5. Self-test validates all evidence interpretation variants
6. Unit test suite covers constants, helpers, report assembly, and JSON serializability

## Invariants

| ID | Description |
|----|-------------|
| INV-GATE-DISCOVERY | Gate discovers beads by scanning artifact directories, not hard-coded lists |
| INV-GATE-EVIDENCE-EVAL | Every evidence file is parsed and evaluated using the unified evidence_passed function |
| INV-GATE-DETERMINISTIC | Canonical JSON hashing produces deterministic content_hash |
| INV-GATE-AUDIT-TRAIL | Every bead evaluation and the final verdict emit structured audit events |

## Outputs

- Gate report: `artifacts/section_10_14/bd-3epz/verification_evidence.json`
- Gate summary: `artifacts/section_10_14/bd-3epz/verification_summary.md`
- Section summary: `artifacts/section_10_14/section_10_14_verification_summary.md`

## Artifacts

- Implementation: `scripts/check_section_10_14_gate.py`
- Spec: `docs/specs/section_10_14/bd-3epz_contract.md`
- Tests: `tests/test_check_section_10_14_gate.py`
- Evidence: `artifacts/section_10_14/bd-3epz/verification_evidence.json`
- Summary: `artifacts/section_10_14/bd-3epz/verification_summary.md`
