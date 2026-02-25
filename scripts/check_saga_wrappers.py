#!/usr/bin/env python3
"""Verification script for bd-3h63: Saga Wrappers with Deterministic Compensations.

Validates spec, Rust implementation, event codes, invariants, core types,
compensation semantics, and test coverage.

Usage:
    python scripts/check_saga_wrappers.py           # human-readable
    python scripts/check_saga_wrappers.py --json     # JSON output
    python scripts/check_saga_wrappers.py --self-test  # self-test mode
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path


BEAD_ID = "bd-3h63"
SECTION = "10.15"
TITLE = "Saga Wrappers with Deterministic Compensations"

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_15" / "bd-3h63_contract.md"
RUST_PATH = ROOT / "crates" / "franken-node" / "src" / "connector" / "saga.rs"
MOD_PATH = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"
TEST_PATH = ROOT / "tests" / "test_check_saga_wrappers.py"
EVIDENCE_PATH = ROOT / "artifacts" / "section_10_15" / "bd-3h63" / "verification_evidence.json"
SUMMARY_PATH = ROOT / "artifacts" / "section_10_15" / "bd-3h63" / "verification_summary.md"

EVENT_CODES = [
    "SAG-001", "SAG-002", "SAG-003", "SAG-004",
    "SAG-005", "SAG-006", "SAG-007", "SAG-008",
]

INVARIANTS = [
    "INV-SAGA-TERMINAL",
    "INV-SAGA-REVERSE-COMP",
    "INV-SAGA-IDEMPOTENT-COMP",
    "INV-SAGA-DETERMINISTIC",
    "INV-SAGA-AUDITABLE",
]

CORE_TYPES = [
    "SagaExecutor",
    "SagaInstance",
    "SagaStepDef",
    "StepOutcome",
    "CompensationTrace",
    "SagaState",
]

REQUIRED_METHODS = [
    "create_saga",
    "execute_step",
    "commit",
    "compensate",
    "get_saga",
    "export_trace",
    "export_audit_log_jsonl",
    "content_hash",
    "saga_count",
]

TERMINAL_STATES = ["Committed", "Compensated"]

MIN_TEST_COUNT = 12


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": passed, "detail": detail}


def _file_text(path: Path) -> str | None:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return None


def run_all() -> dict:
    checks: list[dict] = []

    # --- SOURCE_EXISTS ---
    rust_text = _file_text(RUST_PATH)
    checks.append(_check(
        "SOURCE_EXISTS",
        rust_text is not None,
        f"{RUST_PATH.relative_to(ROOT)} exists" if rust_text else "saga.rs missing",
    ))

    # --- EVENT_CODES ---
    if rust_text:
        for code in EVENT_CODES:
            found = f'"{code}"' in rust_text
            checks.append(_check(
                f"EVENT_CODE:{code}",
                found,
                f"{code} found in Rust" if found else f"{code} missing from Rust",
            ))
    else:
        for code in EVENT_CODES:
            checks.append(_check(f"EVENT_CODE:{code}", False, "saga.rs missing"))

    # --- INVARIANTS ---
    if rust_text:
        for inv in INVARIANTS:
            found = inv in rust_text or inv.replace("-", "_") in rust_text
            checks.append(_check(
                f"INVARIANT:{inv}",
                found,
                f"{inv} found in Rust" if found else f"{inv} missing from Rust",
            ))
    else:
        for inv in INVARIANTS:
            checks.append(_check(f"INVARIANT:{inv}", False, "saga.rs missing"))

    # --- CORE_TYPES ---
    if rust_text:
        for typ in CORE_TYPES:
            found = (f"pub struct {typ}" in rust_text or f"pub enum {typ}" in rust_text)
            checks.append(_check(
                f"CORE_TYPE:{typ}",
                found,
                f"{typ} defined" if found else f"{typ} not defined",
            ))
    else:
        for typ in CORE_TYPES:
            checks.append(_check(f"CORE_TYPE:{typ}", False, "saga.rs missing"))

    # --- REQUIRED_METHODS ---
    if rust_text:
        for method in REQUIRED_METHODS:
            found = f"fn {method}" in rust_text
            checks.append(_check(
                f"METHOD:{method}",
                found,
                f"{method} implemented" if found else f"{method} not found",
            ))
    else:
        for method in REQUIRED_METHODS:
            checks.append(_check(f"METHOD:{method}", False, "saga.rs missing"))

    # --- COMPENSATION_REVERSE ---
    if rust_text:
        has_compensate = "fn compensate" in rust_text
        has_reverse = ".rev()" in rust_text or "reverse" in rust_text.lower()
        found = has_compensate and has_reverse
        checks.append(_check(
            "COMPENSATION_REVERSE",
            found,
            "compensate method with reverse iteration found" if found
            else "compensate or reverse iteration missing",
        ))
    else:
        checks.append(_check("COMPENSATION_REVERSE", False, "saga.rs missing"))

    # --- TERMINAL_STATES ---
    if rust_text:
        for state in TERMINAL_STATES:
            found = state in rust_text
            checks.append(_check(
                f"TERMINAL_STATE:{state}",
                found,
                f"{state} defined" if found else f"{state} not defined",
            ))
    else:
        for state in TERMINAL_STATES:
            checks.append(_check(f"TERMINAL_STATE:{state}", False, "saga.rs missing"))

    # --- TRACE_EXPORT ---
    if rust_text:
        has_export = "fn export_trace" in rust_text
        has_comp_trace = "CompensationTrace" in rust_text
        found = has_export and has_comp_trace
        checks.append(_check(
            "TRACE_EXPORT",
            found,
            "export_trace and CompensationTrace found" if found
            else "export_trace or CompensationTrace missing",
        ))
    else:
        checks.append(_check("TRACE_EXPORT", False, "saga.rs missing"))

    # --- AUDIT_TRAIL ---
    if rust_text:
        found = "fn export_audit_log_jsonl" in rust_text
        checks.append(_check(
            "AUDIT_TRAIL",
            found,
            "export_audit_log_jsonl found" if found
            else "export_audit_log_jsonl missing",
        ))
    else:
        checks.append(_check("AUDIT_TRAIL", False, "saga.rs missing"))

    # --- TEST_COVERAGE ---
    if rust_text:
        test_count = len(re.findall(r"#\[test\]", rust_text))
        checks.append(_check(
            "TEST_COVERAGE",
            test_count >= MIN_TEST_COUNT,
            f"{test_count} tests (>= {MIN_TEST_COUNT} required)",
        ))
    else:
        checks.append(_check("TEST_COVERAGE", False, "saga.rs missing"))

    # --- MODULE_REGISTERED ---
    mod_text = _file_text(MOD_PATH)
    registered = mod_text is not None and "pub mod saga;" in mod_text
    checks.append(_check(
        "MODULE_REGISTERED",
        registered,
        "saga registered in connector/mod.rs" if registered else "not registered",
    ))

    # --- SPEC_EXISTS ---
    spec_text = _file_text(SPEC_PATH)
    checks.append(_check(
        "SPEC_EXISTS",
        spec_text is not None,
        f"{SPEC_PATH.relative_to(ROOT)} exists" if spec_text else "spec missing",
    ))

    # Verify spec references key elements
    if spec_text:
        for code in EVENT_CODES:
            found = code in spec_text
            checks.append(_check(
                f"SPEC_EVENT:{code}",
                found,
                f"{code} in spec" if found else f"{code} missing from spec",
            ))
        for inv in INVARIANTS:
            found = inv in spec_text
            checks.append(_check(
                f"SPEC_INVARIANT:{inv}",
                found,
                f"{inv} in spec" if found else f"{inv} missing from spec",
            ))
        for typ in CORE_TYPES:
            found = typ in spec_text
            checks.append(_check(
                f"SPEC_TYPE:{typ}",
                found,
                f"{typ} in spec" if found else f"{typ} missing from spec",
            ))
    else:
        for code in EVENT_CODES:
            checks.append(_check(f"SPEC_EVENT:{code}", False, "spec missing"))
        for inv in INVARIANTS:
            checks.append(_check(f"SPEC_INVARIANT:{inv}", False, "spec missing"))
        for typ in CORE_TYPES:
            checks.append(_check(f"SPEC_TYPE:{typ}", False, "spec missing"))

    # --- TEST_FILE ---
    test_text = _file_text(TEST_PATH)
    checks.append(_check(
        "TEST_FILE_EXISTS",
        test_text is not None,
        f"{TEST_PATH.relative_to(ROOT)} exists" if test_text else "test file missing",
    ))

    # --- EVIDENCE ---
    evidence_text = _file_text(EVIDENCE_PATH)
    checks.append(_check(
        "EVIDENCE_EXISTS",
        evidence_text is not None,
        "evidence JSON exists" if evidence_text else "evidence missing",
    ))

    # --- SUMMARY ---
    summary_text = _file_text(SUMMARY_PATH)
    checks.append(_check(
        "SUMMARY_EXISTS",
        summary_text is not None,
        "verification summary exists" if summary_text else "summary missing",
    ))

    # --- Compile result ---
    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])
    total = len(checks)
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "checks": checks,
        "passed": passed,
        "failed": failed,
        "total": total,
        "verdict": verdict,
        "all_passed": failed == 0,
        "status": "pass" if failed == 0 else "fail",
    }


def self_test() -> bool:
    """Verify the checker itself is well-formed."""
    result = run_all()
    assert isinstance(result, dict)
    assert result["bead_id"] == BEAD_ID
    assert result["section"] == SECTION
    assert isinstance(result["checks"], list)
    assert isinstance(result["total"], int)
    assert result["total"] > 0
    for check in result["checks"]:
        assert "name" in check
        assert "passed" in check
        assert "detail" in check
        assert isinstance(check["passed"], bool)
    return True


def main() -> None:
    logger = configure_test_logging("check_saga_wrappers")
    if "--self-test" in sys.argv:
        ok = self_test()
        print("self_test passed" if ok else "self_test FAILED")
        sys.exit(0 if ok else 1)

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"=== {TITLE} ({BEAD_ID}) ===")
        print(f"Section: {SECTION}")
        print()
        for check in result["checks"]:
            status = "PASS" if check["passed"] else "FAIL"
            print(f"  [{status}] {check['name']}: {check['detail']}")
        print()
        print(f"Verdict: {result['verdict']} ({result['passed']}/{result['total']})")

    sys.exit(0 if result["all_passed"] else 1)


if __name__ == "__main__":
    main()
