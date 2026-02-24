#!/usr/bin/env python3
"""Verification script for bd-3hw: Remote Idempotency and Saga Semantics Integration.

Validates that the saga module integrates canonical remote idempotency,
capability gating, and saga semantics for multi-step workflows.

Usage:
    python scripts/check_remote_idempotency_saga.py           # human-readable
    python scripts/check_remote_idempotency_saga.py --json     # JSON output
    python scripts/check_remote_idempotency_saga.py --self-test  # self-test mode
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

BEAD_ID = "bd-3hw"
SECTION = "10.11"
TITLE = "Remote Idempotency and Saga Semantics Integration"

SAGA_PATH = ROOT / "crates" / "franken-node" / "src" / "connector" / "saga.rs"
SPEC_PATH = ROOT / "docs" / "specs" / "section_10_11" / "bd-3hw_contract.md"
EVIDENCE_PATH = ROOT / "artifacts" / "section_10_11" / "bd-3hw" / "verification_evidence.json"
SUMMARY_PATH = ROOT / "artifacts" / "section_10_11" / "bd-3hw" / "verification_summary.md"
TEST_PATH = ROOT / "tests" / "test_check_remote_idempotency_saga.py"

EVENT_CODES = [
    "FN-SG-001", "FN-SG-002", "FN-SG-003", "FN-SG-004",
    "FN-SG-005", "FN-SG-006", "FN-SG-007", "FN-SG-008",
    "FN-SG-009", "FN-SG-010", "FN-SG-011", "FN-SG-012",
]

INVARIANTS = [
    "INV-SG-IDEMPOTENT",
    "INV-SG-ORDERED-COMPENSATION",
    "INV-SG-REMOTE-CAP",
    "INV-SG-BULKHEAD-SAFE",
]

EVIDENCE_REQUIRED_FIELDS = [
    "bead_id",
    "section",
    "title",
    "saga_steps_total",
    "compensations_executed",
    "remote_cap_violations",
    "invariants_enforced",
    "event_codes",
    "verdict",
]


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": passed, "detail": detail}


def _file_text(path: Path) -> str | None:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return None


def run_all() -> dict:
    checks: list[dict] = []

    # --- SAGA_EXISTS ---
    saga_text = _file_text(SAGA_PATH)
    checks.append(_check(
        "SAGA_EXISTS",
        saga_text is not None,
        f"{SAGA_PATH.relative_to(ROOT)} exists" if saga_text else "saga.rs missing",
    ))

    # --- EVENT_CODES in saga.rs ---
    # The saga.rs uses short codes (SAG-001 etc.) and the spec uses FN-SG-NNN.
    # We check that the underlying SAG event codes exist in the Rust source,
    # which map to the FN-SG-NNN codes in the spec/evidence.
    if saga_text:
        sag_codes = [
            "SAG-001", "SAG-002", "SAG-003", "SAG-004",
            "SAG-005", "SAG-006", "SAG-007", "SAG-008",
        ]
        for code in sag_codes:
            found = f'"{code}"' in saga_text
            checks.append(_check(
                f"EVENT_CODE:{code}",
                found,
                f"{code} found in saga.rs" if found else f"{code} missing from saga.rs",
            ))
    else:
        for code in ["SAG-001", "SAG-002", "SAG-003", "SAG-004",
                      "SAG-005", "SAG-006", "SAG-007", "SAG-008"]:
            checks.append(_check(f"EVENT_CODE:{code}", False, "saga.rs missing"))

    # --- SPEC_EXISTS ---
    spec_text = _file_text(SPEC_PATH)
    checks.append(_check(
        "SPEC_EXISTS",
        spec_text is not None,
        f"{SPEC_PATH.relative_to(ROOT)} exists" if spec_text else "spec missing",
    ))

    # --- SPEC references FN-SG event codes ---
    if spec_text:
        for code in EVENT_CODES:
            found = code in spec_text
            checks.append(_check(
                f"SPEC_EVENT:{code}",
                found,
                f"{code} in spec" if found else f"{code} missing from spec",
            ))
    else:
        for code in EVENT_CODES:
            checks.append(_check(f"SPEC_EVENT:{code}", False, "spec missing"))

    # --- SPEC references invariants ---
    if spec_text:
        for inv in INVARIANTS:
            found = inv in spec_text
            checks.append(_check(
                f"SPEC_INVARIANT:{inv}",
                found,
                f"{inv} in spec" if found else f"{inv} missing from spec",
            ))
    else:
        for inv in INVARIANTS:
            checks.append(_check(f"SPEC_INVARIANT:{inv}", False, "spec missing"))

    # --- EVIDENCE_EXISTS ---
    evidence_text = _file_text(EVIDENCE_PATH)
    checks.append(_check(
        "EVIDENCE_EXISTS",
        evidence_text is not None,
        "evidence JSON exists" if evidence_text else "evidence missing",
    ))

    # --- EVIDENCE required fields ---
    evidence_data = None
    if evidence_text:
        try:
            evidence_data = json.loads(evidence_text)
        except json.JSONDecodeError:
            evidence_data = None

    if evidence_data:
        for field in EVIDENCE_REQUIRED_FIELDS:
            found = field in evidence_data
            checks.append(_check(
                f"EVIDENCE_FIELD:{field}",
                found,
                f"field '{field}' present" if found else f"field '{field}' missing",
            ))

        # --- saga_steps_total ---
        saga_steps = evidence_data.get("saga_steps_total", 0)
        checks.append(_check(
            "EVIDENCE_SAGA_STEPS",
            isinstance(saga_steps, int) and saga_steps > 0,
            f"saga_steps_total = {saga_steps}" if saga_steps > 0
            else "saga_steps_total must be > 0",
        ))

        # --- compensations_executed ---
        comps = evidence_data.get("compensations_executed", -1)
        checks.append(_check(
            "EVIDENCE_COMPENSATIONS",
            isinstance(comps, int) and comps >= 0,
            f"compensations_executed = {comps}",
        ))

        # --- remote_cap_violations == 0 ---
        violations = evidence_data.get("remote_cap_violations", -1)
        checks.append(_check(
            "EVIDENCE_NO_CAP_VIOLATIONS",
            isinstance(violations, int) and violations == 0,
            f"remote_cap_violations = {violations}" if violations == 0
            else f"remote_cap_violations = {violations} (must be 0)",
        ))

        # --- verdict ---
        verdict_val = evidence_data.get("verdict")
        checks.append(_check(
            "EVIDENCE_VERDICT",
            verdict_val == "PASS",
            f"verdict = {verdict_val}" if verdict_val == "PASS"
            else f"verdict = {verdict_val} (expected PASS)",
        ))
    else:
        for field in EVIDENCE_REQUIRED_FIELDS:
            checks.append(_check(f"EVIDENCE_FIELD:{field}", False, "evidence missing or invalid"))
        checks.append(_check("EVIDENCE_SAGA_STEPS", False, "evidence missing or invalid"))
        checks.append(_check("EVIDENCE_COMPENSATIONS", False, "evidence missing or invalid"))
        checks.append(_check("EVIDENCE_NO_CAP_VIOLATIONS", False, "evidence missing or invalid"))
        checks.append(_check("EVIDENCE_VERDICT", False, "evidence missing or invalid"))

    # --- SUMMARY_EXISTS ---
    summary_text = _file_text(SUMMARY_PATH)
    checks.append(_check(
        "SUMMARY_EXISTS",
        summary_text is not None,
        "verification summary exists" if summary_text else "summary missing",
    ))

    # --- TEST_FILE_EXISTS ---
    test_text = _file_text(TEST_PATH)
    checks.append(_check(
        "TEST_FILE_EXISTS",
        test_text is not None,
        f"{TEST_PATH.relative_to(ROOT)} exists" if test_text else "test file missing",
    ))

    # --- SAGA_IDEMPOTENCY_KEY ---
    if saga_text:
        found = "idempotency_key" in saga_text
        checks.append(_check(
            "SAGA_IDEMPOTENCY_KEY",
            found,
            "idempotency_key field found in saga.rs" if found
            else "idempotency_key field missing from saga.rs",
        ))
    else:
        checks.append(_check("SAGA_IDEMPOTENCY_KEY", False, "saga.rs missing"))

    # --- SAGA_COMPUTATION_NAME ---
    if saga_text:
        found = "computation_name" in saga_text
        checks.append(_check(
            "SAGA_COMPUTATION_NAME",
            found,
            "computation_name field found in saga.rs" if found
            else "computation_name field missing from saga.rs",
        ))
    else:
        checks.append(_check("SAGA_COMPUTATION_NAME", False, "saga.rs missing"))

    # --- SAGA_IS_REMOTE ---
    if saga_text:
        found = "is_remote" in saga_text
        checks.append(_check(
            "SAGA_IS_REMOTE",
            found,
            "is_remote field found in saga.rs" if found
            else "is_remote field missing from saga.rs",
        ))
    else:
        checks.append(_check("SAGA_IS_REMOTE", False, "saga.rs missing"))

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
    logger = configure_test_logging("check_remote_idempotency_saga")
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
