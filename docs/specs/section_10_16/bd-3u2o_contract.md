# bd-3u2o: Substrate Conformance Gate

**Section:** 10.16 | **Type:** task | **Priority:** P1

## Overview

CI conformance gate that blocks merges of features violating the adjacent
substrate policy (bd-2owx). Enforces mandatory/should-use/optional
classification for frankentui, frankensqlite, sqlmodel_rust, and fastapi_rust.

## Substrate Rules

| Substrate | Plane | Mandatory Check |
|-----------|-------|-----------------|
| frankentui | presentation | No raw `println!`/ANSI in mandatory modules; frankentui imports present |
| frankensqlite | persistence | No direct `std::fs` for state; adapter usage required |
| sqlmodel_rust | model | Typed models required; no raw SQL strings |
| fastapi_rust | service | Middleware pipeline usage in API modules |

## Waiver Path

Justified exceptions are recorded in `artifacts/10.16/waiver_registry.json`.
Each waiver must have: substrate, module, rule, justification, owner, expiry.
Expired waivers are treated as violations.

## Event Codes

| Code | Description |
|------|-------------|
| SUBSTRATE_GATE_START | Gate run initiated |
| SUBSTRATE_GATE_VIOLATION | Policy violation detected |
| SUBSTRATE_GATE_WAIVED | Violation covered by active waiver |
| SUBSTRATE_GATE_WAIVER_EXPIRED | Waiver exists but has expired |
| SUBSTRATE_GATE_PASS | Gate passed |
| SUBSTRATE_GATE_FAIL | Gate failed |

## Acceptance Criteria

- CI detects substrate policy noncompliance with remediation hints
- Waiver lookup honors expiry dates
- Gate runs both in CI and locally via conformance tests
- Gate report JSON is machine-parseable with consistent verdicts

## Artifacts

- `.github/workflows/adjacent-substrate-gate.yml`
- `tests/conformance/adjacent_substrate_gate.rs`
- `artifacts/10.16/adjacent_substrate_gate_report.json`
- `scripts/check_substrate_gate.py`
- `tests/test_check_substrate_gate.py`
- `artifacts/section_10_16/bd-3u2o/verification_evidence.json`
- `artifacts/section_10_16/bd-3u2o/verification_summary.md`
