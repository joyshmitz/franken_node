#!/usr/bin/env python3
"""bd-8l9k: Verification script for cross-substrate E2E contract tests.

Usage:
    python3 scripts/check_cross_substrate_e2e.py           # human-readable
    python3 scripts/check_cross_substrate_e2e.py --json     # machine-readable
    python3 scripts/check_cross_substrate_e2e.py --self-test # internal consistency
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# -- File paths ----------------------------------------------------------------

IMPL_FILE = ROOT / "tests" / "e2e" / "adjacent_substrate_flow.rs"
MOD_FILE = ROOT / "tests" / "e2e" / "mod.rs"
SPEC_FILE = ROOT / "docs" / "specs" / "section_10_16" / "bd-8l9k_contract.md"
REPORT_FILE = ROOT / "artifacts" / "10.16" / "adjacent_substrate_e2e_report.json"
TEST_FILE = ROOT / "tests" / "test_check_cross_substrate_e2e.py"
EVIDENCE_FILE = ROOT / "artifacts" / "section_10_16" / "bd-8l9k" / "verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts" / "section_10_16" / "bd-8l9k" / "verification_summary.md"

# -- Required elements ---------------------------------------------------------

REQUIRED_EVENT_CODES = [
    "E2E_SCENARIO_START",
    "E2E_SCENARIO_PASS",
    "E2E_SCENARIO_FAIL",
    "E2E_TRACE_ORPHAN_DETECTED",
    "E2E_REPLAY_MISMATCH",
    "E2E_CONCURRENT_CONFLICT",
]

REQUIRED_ERROR_CODES = [
    "ERR_E2E_SETUP_FAILED",
    "ERR_E2E_TRACE_BROKEN",
    "ERR_E2E_REPLAY_DIVERGED",
    "ERR_E2E_PERSISTENCE_MISMATCH",
    "ERR_E2E_SERVICE_ERROR",
    "ERR_E2E_CONCURRENT_INCONSISTENT",
    "ERR_E2E_TUI_RENDER_FAILED",
    "ERR_E2E_AUDIT_MISSING",
    "ERR_E2E_FENCING_REJECTED",
    "ERR_E2E_SCHEMA_MISMATCH",
]

REQUIRED_INVARIANTS = [
    "INV-E2E-TRACE",
    "INV-E2E-REPLAY",
    "INV-E2E-FENCING",
    "INV-E2E-AUDIT",
    "INV-E2E-ERROR-FIDELITY",
    "INV-E2E-SCHEMA-COMPAT",
    "INV-E2E-CONCURRENT-SAFETY",
]

REQUIRED_SCENARIOS = [
    "operator_status",
    "lease_management",
    "audit_log",
    "error_propagation",
    "concurrent_access",
]

# -- Helpers -------------------------------------------------------------------


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "passed": ok, "detail": detail or ("ok" if ok else "FAIL")}


# -- Check functions -----------------------------------------------------------


def _checks() -> list:
    """Return list of {check, passed, detail} dicts."""
    checks = []
    src = _read(IMPL_FILE)
    mod_src = _read(MOD_FILE)

    # 1. Rust E2E module exists
    checks.append(_check(
        "Rust E2E module exists",
        IMPL_FILE.exists(),
        str(IMPL_FILE),
    ))

    # 2. Wired into tests/e2e/mod.rs
    checks.append(_check(
        "Wired into tests/e2e/mod.rs",
        "pub mod adjacent_substrate_flow;" in mod_src,
        "adjacent_substrate_flow in mod.rs",
    ))

    # 3. Spec contract exists
    checks.append(_check(
        "Spec contract exists",
        SPEC_FILE.exists(),
        str(SPEC_FILE),
    ))

    # 4. Report artifact exists
    report_valid = False
    if REPORT_FILE.exists():
        try:
            report = json.loads(REPORT_FILE.read_text(encoding="utf-8"))
            report_valid = (
                "scenarios" in report
                and "trace_coverage" in report
                and "replay_results" in report
            )
        except (json.JSONDecodeError, OSError):
            pass
    checks.append(_check(
        "Report artifact exists and valid",
        report_valid,
        str(REPORT_FILE),
    ))

    # 5. Test file exists
    checks.append(_check(
        "Test file exists",
        TEST_FILE.exists(),
        str(TEST_FILE),
    ))

    # 6. Evidence exists with PASS verdict
    evidence_pass = False
    if EVIDENCE_FILE.exists():
        try:
            ev = json.loads(EVIDENCE_FILE.read_text(encoding="utf-8"))
            evidence_pass = ev.get("verdict") == "PASS"
        except (json.JSONDecodeError, OSError):
            pass
    checks.append(_check(
        "Evidence exists with PASS verdict",
        evidence_pass,
        str(EVIDENCE_FILE),
    ))

    # 7. Summary file exists
    checks.append(_check(
        "Verification summary exists",
        SUMMARY_FILE.exists(),
        str(SUMMARY_FILE),
    ))

    # 8. Scenario coverage — all five required scenarios present
    for scenario in REQUIRED_SCENARIOS:
        fn_name = f"scenario_{scenario}"
        checks.append(_check(
            f"Scenario '{scenario}' defined",
            f"fn {fn_name}" in src or f"pub fn {fn_name}" in src,
            fn_name,
        ))

    # 9. Trace propagation scenario
    checks.append(_check(
        "Trace propagation scenario defined",
        "fn scenario_trace_propagation" in src,
    ))

    # 10. Replay determinism scenario
    checks.append(_check(
        "Replay determinism scenario defined",
        "fn scenario_replay_determinism" in src,
    ))

    # 11. Trace verification — find_orphans function
    checks.append(_check(
        "Trace orphan detection (find_orphans)",
        "fn find_orphans" in src,
    ))

    # 12. Trace completeness check
    checks.append(_check(
        "Trace completeness check (is_complete)",
        "fn is_complete" in src,
    ))

    # 13. Replay determinism verification function
    checks.append(_check(
        "Replay determinism verification function",
        "fn verify_replay_determinism" in src,
    ))

    # 14. Event codes defined
    for code in REQUIRED_EVENT_CODES:
        checks.append(_check(
            f"Event code {code} defined",
            code in src,
        ))

    # 15. Error codes defined
    for code in REQUIRED_ERROR_CODES:
        checks.append(_check(
            f"Error code {code} defined",
            code in src,
        ))

    # 16. Invariants defined
    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(
            f"Invariant {inv} defined",
            inv in src,
        ))

    # 17. Invariants module exists
    checks.append(_check(
        "Invariants module defined",
        "pub mod invariants" in src or "mod invariants" in src,
    ))

    # 18. Schema version e2e-v1.0
    checks.append(_check(
        "Schema version e2e-v1.0",
        'e2e-v1.0' in src,
    ))

    # 19. BTreeMap usage for determinism
    checks.append(_check(
        "BTreeMap usage for determinism",
        "BTreeMap" in src,
    ))

    # 20. Serde derives
    checks.append(_check(
        "Serialize/Deserialize derives",
        "Serialize" in src and "Deserialize" in src,
    ))

    # 21. Rust unit tests count
    test_count = src.count("#[test]")
    checks.append(_check(
        f"Rust unit tests ({test_count})",
        test_count >= 25,
        f"{test_count} tests found",
    ))

    # 22. Four substrate variants
    for sub in ["FrankenTui", "FastapiRust", "SqlmodelRust", "FrankenSqlite"]:
        checks.append(_check(
            f"Substrate variant {sub}",
            sub in src,
        ))

    # 23. MockClock for deterministic time
    checks.append(_check(
        "MockClock defined",
        "MockClock" in src,
    ))

    # 24. FencingToken type
    checks.append(_check(
        "FencingToken type defined",
        "FencingToken" in src,
    ))

    # 25. AuditLog with verify_chain
    checks.append(_check(
        "AuditLog with verify_chain",
        "fn verify_chain" in src,
    ))

    # 26. StructuredError type
    checks.append(_check(
        "StructuredError type defined",
        "StructuredError" in src,
    ))

    # 27. ScenarioRunner
    checks.append(_check(
        "ScenarioRunner defined",
        "ScenarioRunner" in src,
    ))

    # 28. run_all_scenarios function
    checks.append(_check(
        "run_all_scenarios function",
        "fn run_all_scenarios" in src,
    ))

    return checks


def self_test() -> dict:
    """Internal consistency checks for the gate script itself."""
    checks = []

    # Constants
    checks.append(_check("REQUIRED_EVENT_CODES == 6", len(REQUIRED_EVENT_CODES) == 6))
    checks.append(_check("REQUIRED_ERROR_CODES == 10", len(REQUIRED_ERROR_CODES) == 10))
    checks.append(_check("REQUIRED_INVARIANTS >= 5", len(REQUIRED_INVARIANTS) >= 5))
    checks.append(_check("REQUIRED_SCENARIOS >= 5", len(REQUIRED_SCENARIOS) >= 5))

    # _checks returns list
    result = _checks()
    checks.append(_check("_checks returns list", isinstance(result, list)))
    checks.append(_check("_checks returns dicts", all(isinstance(c, dict) for c in result)))
    checks.append(_check("_checks >= 40 checks", len(result) >= 40, f"{len(result)} checks"))

    # Check structure
    for c in result[:5]:
        checks.append(_check(
            f"check '{c['check']}' has required keys",
            all(k in c for k in ["check", "passed", "detail"]),
        ))

    # Full run
    full = run_all()
    checks.append(_check("run_all has bead_id", full.get("bead_id") == "bd-8l9k"))
    checks.append(_check("run_all has section", full.get("section") == "10.16"))
    checks.append(_check("run_all has verdict", full.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_all has events", isinstance(full.get("events"), list)))
    checks.append(_check("run_all has summary", isinstance(full.get("summary"), str)))
    checks.append(_check("run_all has timestamp", isinstance(full.get("timestamp"), str)))

    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "name": "check_cross_substrate_e2e",
        "bead": "bd-8l9k",
        "section": "10.16",
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": verdict,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "events": [{"code": code, "status": "verified"} for code in REQUIRED_EVENT_CODES],
        "summary": f"self-test: {passed}/{len(checks)} checks passed, verdict={verdict}",
    }


def run_all() -> dict:
    """Run all checks and return structured result."""
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])
    verdict = "PASS" if failed == 0 else "FAIL"

    events = []
    for code in REQUIRED_EVENT_CODES:
        events.append({"code": code, "status": "defined"})

    summary_lines = [
        f"bd-8l9k: Cross-Substrate Contract Tests E2E Validation",
        f"Checks: {passed}/{len(checks)} passing",
        f"Verdict: {verdict}",
    ]
    if failed > 0:
        failing = [c for c in checks if not c["passed"]]
        for c in failing[:5]:
            summary_lines.append(f"  FAIL: {c['check']}: {c['detail']}")

    return {
        "bead_id": "bd-8l9k",
        "title": "Cross-Substrate Contract Tests: End-to-End Behavior Validation",
        "section": "10.16",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "events": events,
        "summary": "\n".join(summary_lines),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# -- CLI -----------------------------------------------------------------------


def main():
    if "--self-test" in sys.argv:
        result = self_test()
        for c in result["checks"]:
            status = "PASS" if c["passed"] else "FAIL"
            print(f"  [{status}] {c['check']}")
        print(f"\nself-test: {result['passed']}/{len(result['checks'])} {result['verdict']}")
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"# {result['bead_id']}: {result['title']}")
        print(f"Section: {result['section']} | Verdict: {result['verdict']}")
        print(f"Checks: {result['passed']}/{result['total']} passing\n")
        for c in result["checks"]:
            status = "PASS" if c["passed"] else "FAIL"
            print(f"  [{status}] {c['check']}: {c['detail']}")
        if result["failed"] > 0:
            print(f"\n{result['failed']} check(s) failed.")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
