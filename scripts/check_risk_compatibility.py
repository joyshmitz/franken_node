#!/usr/bin/env python3
"""Verification script for bd-s4cu: Risk Control — Compatibility Illusion.

Checks that the risk control artefacts for the Compatibility Illusion risk
are present, complete, and internally consistent.

Usage:
    python scripts/check_risk_compatibility.py          # human-readable
    python scripts/check_risk_compatibility.py --json    # machine-readable
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

RESULTS: list[dict] = []


def _check(name: str, passed: bool, detail: str) -> None:
    RESULTS.append({"name": name, "passed": passed, "detail": detail})


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_spec_exists() -> None:
    p = ROOT / "docs" / "specs" / "section_12" / "bd-s4cu_contract.md"
    _check("spec_exists", p.is_file(), f"Spec file {'found' if p.is_file() else 'MISSING'}: {p}")


def check_risk_policy_exists() -> None:
    p = ROOT / "docs" / "policy" / "risk_compatibility_illusion.md"
    _check("risk_policy_exists", p.is_file(), f"Risk policy {'found' if p.is_file() else 'MISSING'}: {p}")


def check_risk_documented() -> None:
    p = ROOT / "docs" / "policy" / "risk_compatibility_illusion.md"
    if not p.is_file():
        _check("risk_documented", False, "Risk policy file missing")
        return
    text = p.read_text()
    has_description = "Compatibility Illusion" in text
    has_impact = "Impact" in text
    has_likelihood = "Likelihood" in text
    ok = has_description and has_impact and has_likelihood
    _check("risk_documented", ok, "Risk description, impact, and likelihood documented" if ok else "Missing risk documentation sections")


def check_countermeasures() -> None:
    p = ROOT / "docs" / "policy" / "risk_compatibility_illusion.md"
    if not p.is_file():
        _check("countermeasures", False, "Risk policy file missing")
        return
    text = p.read_text()
    has_oracle = "lockstep oracle" in text.lower() or "Lockstep Oracle" in text
    has_receipts = "divergence receipt" in text.lower() or "Divergence Receipt" in text
    has_monitoring = "monitoring" in text.lower() or "Monitoring" in text
    ok = has_oracle and has_receipts and has_monitoring
    _check("countermeasures", ok, "All countermeasures documented" if ok else "Missing countermeasure documentation")


def check_threshold() -> None:
    spec = ROOT / "docs" / "specs" / "section_12" / "bd-s4cu_contract.md"
    policy = ROOT / "docs" / "policy" / "risk_compatibility_illusion.md"
    found_spec = False
    found_policy = False
    if spec.is_file():
        found_spec = "95%" in spec.read_text()
    if policy.is_file():
        found_policy = "95%" in policy.read_text()
    ok = found_spec and found_policy
    _check("threshold", ok, "95% threshold present in spec and policy" if ok else "95% threshold missing from spec or policy")


def check_event_codes() -> None:
    p = ROOT / "docs" / "specs" / "section_12" / "bd-s4cu_contract.md"
    if not p.is_file():
        _check("event_codes", False, "Spec file missing")
        return
    text = p.read_text()
    codes = ["RCR-001", "RCR-002", "RCR-003", "RCR-004"]
    missing = [c for c in codes if c not in text]
    ok = len(missing) == 0
    _check("event_codes", ok, "All event codes present" if ok else f"Missing event codes: {missing}")


def check_invariants() -> None:
    p = ROOT / "docs" / "specs" / "section_12" / "bd-s4cu_contract.md"
    if not p.is_file():
        _check("invariants", False, "Spec file missing")
        return
    text = p.read_text()
    invariants = ["INV-RCR-ORACLE", "INV-RCR-RECEIPTS", "INV-RCR-THRESHOLD", "INV-RCR-MONITOR"]
    missing = [i for i in invariants if i not in text]
    ok = len(missing) == 0
    _check("invariants", ok, "All invariants present" if ok else f"Missing invariants: {missing}")


def check_alert_pipeline() -> None:
    p = ROOT / "docs" / "policy" / "risk_compatibility_illusion.md"
    if not p.is_file():
        _check("alert_pipeline", False, "Risk policy file missing")
        return
    text = p.read_text()
    has_warning = "warning" in text.lower() or "WARNING" in text
    has_critical = "critical" in text.lower() or "CRITICAL" in text
    has_97 = "97%" in text
    has_pipeline = "alert" in text.lower() or "Alert" in text
    ok = has_warning and has_critical and has_97 and has_pipeline
    _check("alert_pipeline", ok, "Alert pipeline documented with warning and critical thresholds" if ok else "Alert pipeline documentation incomplete")


def check_spec_keywords() -> None:
    p = ROOT / "docs" / "specs" / "section_12" / "bd-s4cu_contract.md"
    if not p.is_file():
        _check("spec_keywords", False, "Spec file missing")
        return
    text = p.read_text()
    keywords = ["Compatibility Illusion", "lockstep oracle", "divergence receipt", "bd-s4cu"]
    missing = [k for k in keywords if k.lower() not in text.lower()]
    ok = len(missing) == 0
    _check("spec_keywords", ok, "All spec keywords present" if ok else f"Missing keywords: {missing}")


def check_escalation() -> None:
    p = ROOT / "docs" / "policy" / "risk_compatibility_illusion.md"
    if not p.is_file():
        _check("escalation", False, "Risk policy file missing")
        return
    text = p.read_text()
    ok = "escalation" in text.lower() or "Escalation" in text
    _check("escalation", ok, "Escalation procedures documented" if ok else "Escalation procedures missing")


def check_evidence_requirements() -> None:
    p = ROOT / "docs" / "policy" / "risk_compatibility_illusion.md"
    if not p.is_file():
        _check("evidence_requirements", False, "Risk policy file missing")
        return
    text = p.read_text()
    ok = "evidence" in text.lower() and "review" in text.lower()
    _check("evidence_requirements", ok, "Evidence requirements for review documented" if ok else "Evidence requirements missing")


def check_verification_evidence() -> None:
    p = ROOT / "artifacts" / "section_12" / "bd-s4cu" / "verification_evidence.json"
    if not p.is_file():
        _check("verification_evidence", False, f"Evidence file MISSING: {p}")
        return
    try:
        data = json.loads(p.read_text())
        ok = data.get("bead_id") == "bd-s4cu" and data.get("status") == "pass"
        _check("verification_evidence", ok, "Evidence file valid" if ok else "Evidence file has incorrect bead_id or status")
    except (json.JSONDecodeError, KeyError) as exc:
        _check("verification_evidence", False, f"Evidence file parse error: {exc}")


def check_verification_summary() -> None:
    p = ROOT / "artifacts" / "section_12" / "bd-s4cu" / "verification_summary.md"
    _check("verification_summary", p.is_file(), f"Summary file {'found' if p.is_file() else 'MISSING'}: {p}")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_risk_policy_exists,
    check_risk_documented,
    check_countermeasures,
    check_threshold,
    check_event_codes,
    check_invariants,
    check_alert_pipeline,
    check_spec_keywords,
    check_escalation,
    check_evidence_requirements,
    check_verification_evidence,
    check_verification_summary,
]


def run_all() -> dict:
    RESULTS.clear()
    for fn in ALL_CHECKS:
        fn()
    passed = sum(1 for r in RESULTS if r["passed"])
    total = len(RESULTS)
    return {
        "bead_id": "bd-s4cu",
        "section": "12",
        "title": "Risk Control — Compatibility Illusion",
        "passed": passed,
        "total": total,
        "all_passed": passed == total,
        "checks": list(RESULTS),
    }


def self_test() -> None:
    """Smoke-test: run all checks and assert the structure is valid."""
    result = run_all()
    assert isinstance(result, dict)
    assert result["bead_id"] == "bd-s4cu"
    assert result["section"] == "12"
    assert isinstance(result["checks"], list)
    assert result["total"] == len(ALL_CHECKS)
    assert result["passed"] <= result["total"]
    assert isinstance(result["all_passed"], bool)
    for check in result["checks"]:
        assert "name" in check
        assert "passed" in check
        assert "detail" in check
    print("self_test passed")


def main() -> None:
    logger = configure_test_logging("check_risk_compatibility")
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-s4cu: Risk Control — Compatibility Illusion")
        print(f"{'=' * 55}")
        for check in result["checks"]:
            mark = "PASS" if check["passed"] else "FAIL"
            print(f"  [{mark}] {check['name']}: {check['detail']}")
        print(f"\n  {result['passed']}/{result['total']} checks passed")
        if not result["all_passed"]:
            sys.exit(1)


if __name__ == "__main__":
    main()
