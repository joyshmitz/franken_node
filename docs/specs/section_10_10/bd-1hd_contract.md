# bd-1hd Contract: Release Gate Vector Suites

**Bead:** bd-1hd
**Section:** 10.10 (FCP-Inspired Hardening)
**Status:** Active

## Purpose

Promote canonical trust protocol golden vectors from 10.13 and 10.14 to
mandatory release gates.  No product release ships without passing all
vector suites.

## Vector Suite Manifest

The manifest `vectors/release_gate_manifest.json` enumerates every golden
vector suite required for release.  Each entry specifies:

| Field           | Type   | Description                          |
|-----------------|--------|--------------------------------------|
| suite_name      | String | Human-readable suite name            |
| source_section  | String | Source section (10.13 or 10.14)      |
| vector_file     | String | Relative path to vector JSON file    |
| min_pass_count  | int    | Minimum pass count required          |
| version         | String | Vector suite version                 |
| schema_ref      | String | Schema reference for validation      |
| features        | list   | Protocol features covered            |

## Event Codes

| Code    | Severity | Description                                    |
|---------|----------|------------------------------------------------|
| RGV-001 | INFO     | Release gate started                           |
| RGV-002 | INFO     | Vector suite started                           |
| RGV-003 | INFO     | Vector suite passed                            |
| RGV-004 | ERROR    | Vector suite failed                            |
| RGV-005 | ERROR    | Regression detected in previously passing vector|
| RGV-006 | WARN     | Coverage gap detected                          |
| RGV-007 | INFO     | Release gate completed                         |

## Invariants

- **INV-RGV-BLOCK** — Release gate fails the build if any vector suite has
  failures.
- **INV-RGV-REGRESSION** — Regressions are always hard failures with no
  skip mechanism.
- **INV-RGV-VERSIONED** — Each vector suite carries a version number
  recorded in the gate verdict.
- **INV-RGV-COVERAGE** — Coverage gaps are reported prominently but as
  warnings (not failures).

## Error Codes

| Code                       | Description                              |
|----------------------------|------------------------------------------|
| ERR_RGV_MANIFEST_MISSING   | Release gate manifest not found          |
| ERR_RGV_MANIFEST_INVALID   | Manifest JSON parsing failed             |
| ERR_RGV_VECTOR_FILE_MISSING| Vector file referenced in manifest absent|
| ERR_RGV_SUITE_FAILED       | Vector suite has failures                |
| ERR_RGV_REGRESSION         | Previously passing vector now fails      |

## Acceptance Criteria

1. `vectors/release_gate_manifest.json` lists all vector suites from 10.13/10.14.
2. `scripts/check_release_vectors.py --json` runs all suites with structured verdict.
3. Regression diagnostics include vector ID, expected vs actual.
4. Coverage report in `artifacts/section_10_10/bd-1hd/vector_coverage.json`.
5. >= 15 checks in verification script.
6. Self-test mode validates the script structure.

## Dependencies

- bd-3n2u (10.13 golden vectors) — source suites
- bd-jjm (canonical serialization) — serialization vectors

## File Layout

```
docs/specs/section_10_10/bd-1hd_contract.md (this file)
vectors/release_gate_manifest.json
scripts/check_release_vectors.py
tests/test_check_release_vectors.py
artifacts/section_10_10/bd-1hd/verification_evidence.json
artifacts/section_10_10/bd-1hd/verification_summary.md
artifacts/section_10_10/bd-1hd/vector_coverage.json
```
