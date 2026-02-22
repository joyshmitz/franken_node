# Bootstrap Foundation Verification Gate (bd-3ohj)

## Purpose

The foundation verification gate is the master gate for the BOOTSTRAP section.
It validates that all bootstrap beads are complete and verified before the
bootstrap foundation can be declared stable. The gate aggregates evidence from
every upstream bead, checks structural integrity of key deliverables, and
produces a machine-readable verdict.

The gate enforces a **fail-closed** policy: any missing evidence, unstable
logs, or nondeterministic outcomes cause the gate to reject the foundation.

## Evidence Consumption

The gate consumes the following evidence dimensions:

| Dimension | Source | Criterion |
|-----------|--------|-----------|
| **Evidence completeness** | `artifacts/section_bootstrap/bd-*/verification_evidence.json` | Every bead directory contains a parseable evidence file with `verdict: "PASS"` and all required fields (`bead_id`, `section`, `verdict`). |
| **Matrix coverage** | Per-bead evidence aggregation | All discovered beads must have passing verdicts. Coverage percentage must reach 100% of discovered beads. |
| **E2E outcomes** | `artifacts/section_bootstrap/bd-3k9t/foundation_e2e_summary.json` | Foundation E2E suite verdict is `PASS` with all required journeys covered. |
| **Baseline check artifacts** | `artifacts/section_bootstrap/bd-2a3/baseline_checks.json` | Baseline RCH sequence has been executed and results are documented with deterministic provenance. |
| **Docs validation** | `docs/architecture/tri_kernel_ownership_contract.md`, `tests/conformance/ownership_boundary_checks.rs` | Key architectural and conformance artifacts exist on disk. |

## Fail-Closed Policy

The gate fails (exit code 1) under any of the following conditions:

1. **Missing evidence** -- Any bootstrap bead directory lacks a
   `verification_evidence.json` file.
2. **Parse failure** -- Any evidence file is not valid JSON or is missing
   required fields (`bead_id`, `section`, `verdict`).
3. **Failed verdict** -- Any bead evidence file has a `verdict` value other
   than `"PASS"`.
4. **Missing key artifacts** -- The ownership contract doc or conformance test
   file does not exist.
5. **Nondeterministic outcomes** -- Evidence files contain inconsistent or
   unstable data that cannot be reproduced.

The gate exits 0 only when every sub-verdict passes.

## Verdict Schema

The gate emits a JSON report with the following structure:

```json
{
  "bead": "bd-3ohj",
  "title": "Bootstrap Foundation Verification Gate",
  "section": "bootstrap",
  "gate_type": "bootstrap_foundation",
  "verdict": "PASS | FAIL",
  "summary": {
    "beads_discovered": <int>,
    "beads_passed": <int>,
    "beads_failed": <int>,
    "key_artifacts_present": <bool>,
    "dimensions": {
      "evidence_completeness": "PASS | FAIL",
      "matrix_coverage": "PASS | FAIL",
      "docs_validation": "PASS | FAIL",
      "upstream_verdicts": "PASS | FAIL"
    }
  },
  "bead_results": [
    {
      "bead_id": "bd-xxx",
      "verdict": "PASS | FAIL",
      "detail": "<string>"
    }
  ],
  "key_artifact_checks": [
    {
      "path": "<relative-path>",
      "exists": true | false
    }
  ],
  "event_log": [
    {
      "event_code": "BOOT-GATE-001",
      "detail": "..."
    }
  ]
}
```

### Per-dimension pass/fail

The `summary.dimensions` object provides a machine-readable per-dimension
pass/fail breakdown. A dimension is `"PASS"` only when all checks within that
dimension succeed. The top-level `verdict` is `"PASS"` only when every
dimension is `"PASS"`.

## Event Codes

| Code | Meaning |
|------|---------|
| `BOOT-GATE-001` | Gate execution started. Emitted once at the beginning of every gate run. |
| `BOOT-GATE-002` | Bead evidence scanned. Emitted for each bead directory discovered, with per-bead pass/fail detail. |
| `BOOT-GATE-003` | Key artifact check completed. Emitted after verifying existence of required architectural artifacts. |
| `BOOT-GATE-004` | Gate verdict computed. Emitted once after all checks complete, carrying the final verdict. |
| `BOOT-GATE-005` | Remediation required. Emitted when the gate verdict is FAIL, with actionable guidance per failing dimension. |

## Remediation Guidance

| Failure Mode | Remediation |
|-------------|-------------|
| Missing evidence file | Re-run the upstream bead's verification pipeline to generate `verification_evidence.json`. Check that the bead directory exists under `artifacts/section_bootstrap/`. |
| Invalid JSON in evidence | Regenerate the evidence file. Ensure the generating script produces valid UTF-8 JSON. |
| Missing required fields | Ensure the evidence generator emits `bead_id`, `section`, and `verdict` at the top level of every evidence file. |
| Verdict is not PASS | Investigate the upstream bead's verification summary for failure details. Fix the root cause and re-run the upstream gate. |
| Missing key artifacts | Restore the missing file from version control or regenerate it. Required paths: `docs/architecture/tri_kernel_ownership_contract.md`, `tests/conformance/ownership_boundary_checks.rs`. |

## CI Integration

Add to bootstrap pipelines:

```bash
python3 scripts/check_foundation_gate.py --json
```

Pipeline behavior:

- Fail the build if the command exits non-zero.
- Persist the JSON report as a CI artifact.
- Use the verdict to gate downstream section builds.

## Related Artifacts

- Gate script: `scripts/check_foundation_gate.py`
- Unit tests: `tests/test_check_foundation_gate.py`
- Evidence: `artifacts/section_bootstrap/bd-3ohj/verification_evidence.json`
- Upstream E2E harness: `docs/specs/bootstrap_e2e_harness.md`
- Upstream config contract: `docs/specs/bootstrap_config_contract.md`
- Upstream init contract: `docs/specs/bootstrap_init_contract.md`
- Upstream doctor contract: `docs/specs/bootstrap_doctor_contract.md`
