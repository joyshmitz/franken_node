# BOOTSTRAP Section Verification Gate Contract (`bd-3ohj`)

## Goal

Provide a section-level verification gate for the BOOTSTRAP section that
aggregates and verifies all bootstrap bead artifacts, computes aggregate
pass/fail metrics, and emits a machine-readable gate report.

## Scope

This gate covers all beads delivered under the BOOTSTRAP section:

| Bead | Title |
|------|-------|
| `bd-2a3` | Baseline RCH sequence and quality checks |
| `bd-n9r` | Config profile resolution |
| `bd-1pk` | Doctor command diagnostics |
| `bd-32e` | Init profile bootstrap |
| `bd-3k9t` | Foundation E2E suite bundle with structured logs |

## Gate Mechanics

### Discovery

The gate discovers bead directories under `artifacts/section_bootstrap/`
by scanning for directories whose name starts with `bd-`. The gate bead
itself (`bd-3ohj`) is excluded from discovery to avoid self-reference.

### Evidence Evaluation

Each discovered bead must have:
- `verification_evidence.json` -- machine-readable evidence payload
- `verification_summary.md` -- human-readable summary

The gate uses a multi-format `evidence_passed()` function that handles
the diverse evidence formats used by bootstrap beads:

1. `"verdict": "PASS"` -- explicit verdict field
2. `"overall_pass": true` / `"all_passed": true` -- boolean flags
3. `"status": "pass"` -- status string
4. `"status": "implemented_with_baseline_quality_debt"` -- bootstrap-specific pass
5. `"acceptance_criteria"` list with all `"status": "pass"` entries
6. Nested gate verdicts (e.g. `diagnostic_contract_gate.verdict`)
7. `"overall_status"` containing the substring `"pass"`
8. `"verifier_results.check_report.verdict"` == `"PASS"`
9. `"checks"` list where all items have `"pass": true`
10. `"checks"` dict with `total > 0` and `failed == 0`

### Gate Checks

| Gate Check | Criterion |
|------------|-----------|
| `GATE-BOOT-DISCOVERY` | At least 4 beads discovered |
| `GATE-BOOT-COVERAGE` | >= 80% of discovered beads pass |
| `GATE-BOOT-ALL-EVIDENCE` | All beads have `verification_evidence.json` |
| `GATE-BOOT-ALL-SUMMARIES` | All beads have `verification_summary.md` |

### Verdict

The gate issues `PASS` if and only if all four gate checks pass.

## Artifacts

- Gate script: `scripts/check_section_bootstrap_gate.py`
- Unit tests: `tests/test_check_section_bootstrap_gate.py`
- Section summary: `artifacts/section_bootstrap/section_bootstrap_verification_summary.md`
- Gate evidence: `artifacts/section_bootstrap/bd-3ohj/verification_evidence.json`
- Gate summary: `artifacts/section_bootstrap/bd-3ohj/verification_summary.md`

## CLI Interface

```
python3 scripts/check_section_bootstrap_gate.py           # human-readable output
python3 scripts/check_section_bootstrap_gate.py --json    # machine-readable JSON
python3 scripts/check_section_bootstrap_gate.py --self-test  # run internal self-test
```

## Acceptance Criteria

1. The gate discovers all bootstrap beads and excludes its own bead directory.
2. The `evidence_passed()` function correctly classifies all bootstrap evidence formats.
3. The gate report is JSON-serializable and includes a deterministic content hash.
4. The `--self-test` flag passes with >= 10 checks covering evidence format variants.
5. All unit tests in the test suite pass.
