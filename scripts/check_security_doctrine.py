#!/usr/bin/env python3
"""Verification script for bd-ud5h: Security and Trust Product Doctrine.

Checks that all adversary classes, trust-native surfaces, safety guarantee
targets, event codes, and invariants are documented.

Usage:
    python scripts/check_security_doctrine.py [--json]
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

RESULTS: list[dict] = []


def _check(name: str, passed: bool, detail: str = "") -> bool:
    RESULTS.append({"name": name, "pass": passed, "detail": detail})
    return passed


def check_files_exist() -> int:
    files = {
        "doctrine_doc": "docs/doctrine/security_and_trust.md",
        "spec_contract": "docs/specs/section_6/bd-ud5h_contract.md",
    }
    ok = 0
    for label, rel in files.items():
        if _check(f"file_exists:{label}", (ROOT / rel).is_file(), rel):
            ok += 1
    return ok


def check_adversary_classes() -> int:
    doc = ROOT / "docs/doctrine/security_and_trust.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    classes = {
        "ADV-01": "Supply-Chain Compromise",
        "ADV-02": "Credential Exfiltration",
        "ADV-03": "Policy Evasion",
        "ADV-04": "Delayed Payload",
        "ADV-05": "Operational Confusion",
    }
    ok = 0
    for cid, name in classes.items():
        if _check(f"adversary:{cid}", cid in text, f"{cid}: {name}"):
            ok += 1
    return ok


def check_adversary_mitigations() -> int:
    doc = ROOT / "docs/doctrine/security_and_trust.md"
    if not doc.is_file():
        return 0
    text = doc.read_text().lower()
    mitigation_keywords = [
        "provenance",
        "revocation",
        "sandbox",
        "capability",
        "containment",
        "deterministic replay",
        "audit",
        "anomaly detection",
        "signed",
    ]
    ok = 0
    for kw in mitigation_keywords:
        if _check(f"mitigation:{kw}", kw in text, f"mitigation keyword: {kw}"):
            ok += 1
    return ok


def check_trust_surfaces() -> int:
    doc = ROOT / "docs/doctrine/security_and_trust.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    surfaces = {
        "TNS-01": "Extension Trust Cards",
        "TNS-02": "Policy-Visible Compatibility",
        "TNS-03": "Revocation-First",
        "TNS-04": "Signed Incident Receipts",
        "TNS-05": "Autonomous Containment",
    }
    ok = 0
    for sid, name in surfaces.items():
        if _check(f"surface:{sid}", sid in text, f"{sid}: {name}"):
            ok += 1
    return ok


def check_safety_targets() -> int:
    doc = ROOT / "docs/doctrine/security_and_trust.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    targets = {
        "SGT-01": "false-negative",
        "SGT-02": "false-positive",
        "SGT-03": "deterministic replay",
        "SGT-04": "degraded-mode",
    }
    ok = 0
    for tid, kw in targets.items():
        if _check(f"safety_target:{tid}", tid in text and kw.lower() in text.lower(), f"{tid}: {kw}"):
            ok += 1
    return ok


def check_quantitative_thresholds() -> int:
    doc = ROOT / "docs/doctrine/security_and_trust.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    thresholds = [
        ("false_neg_bound", "0.1%"),
        ("false_pos_bound", "1.0%"),
        ("replay_target", "100%"),
    ]
    ok = 0
    for label, val in thresholds:
        if _check(f"threshold:{label}", val in text, f"threshold: {val}"):
            ok += 1
    return ok


def check_event_codes() -> int:
    doc = ROOT / "docs/doctrine/security_and_trust.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    codes = ["SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005"]
    ok = 0
    for code in codes:
        if _check(f"event_code:{code}", code in text, code):
            ok += 1
    return ok


def check_invariants() -> int:
    doc = ROOT / "docs/doctrine/security_and_trust.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    invariants = [
        "INV-SEC-THREAT",
        "INV-SEC-SURFACE",
        "INV-SEC-SAFETY",
        "INV-SEC-REVIEW",
    ]
    ok = 0
    for inv in invariants:
        if _check(f"invariant:{inv}", inv in text, inv):
            ok += 1
    return ok


def check_cross_section_mapping() -> int:
    doc = ROOT / "docs/doctrine/security_and_trust.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    sections = ["10.2", "10.3", "10.4", "10.5", "10.8", "10.13", "10.14", "10.17"]
    ok = 0
    for sec in sections:
        if _check(f"cross_section:{sec}", sec in text, f"cross-section: {sec}"):
            ok += 1
    return ok


def check_required_sections() -> int:
    doc = ROOT / "docs/doctrine/security_and_trust.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    headings = [
        "Problem Statement",
        "Product Goal",
        "Threat Model",
        "Trust-Native Product Surfaces",
        "Safety Guarantee Targets",
        "Cross-Section",
    ]
    ok = 0
    for h in headings:
        if _check(f"section:{h}", h in text, f"section: {h}"):
            ok += 1
    return ok


def check_spec_contract() -> int:
    spec = ROOT / "docs/specs/section_6/bd-ud5h_contract.md"
    if not spec.is_file():
        return 0
    text = spec.read_text()
    keywords = ["bd-ud5h", "ADV-01", "TNS-01", "SGT-01", "SEC-001", "INV-SEC"]
    ok = 0
    for kw in keywords:
        if _check(f"spec:{kw}", kw in text, f"spec: {kw}"):
            ok += 1
    return ok


def run_all() -> dict:
    RESULTS.clear()
    check_files_exist()
    check_adversary_classes()
    check_adversary_mitigations()
    check_trust_surfaces()
    check_safety_targets()
    check_quantitative_thresholds()
    check_event_codes()
    check_invariants()
    check_cross_section_mapping()
    check_required_sections()
    check_spec_contract()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "bead_id": "bd-ud5h",
        "title": "Security and Trust Product Doctrine",
        "section": "6",
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": RESULTS,
    }


def self_test():
    assert callable(check_adversary_classes)
    assert callable(check_trust_surfaces)
    assert callable(check_safety_targets)
    result = run_all()
    assert "verdict" in result
    assert result["total"] > 0
    print("self_test: OK")


def main():
    logger = configure_test_logging("check_security_doctrine")
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-ud5h Security Doctrine: {result['verdict']}")
        print(f"  Checks: {result['passed']}/{result['total']}")
        if result["failed"] > 0:
            print(f"  FAILED ({result['failed']}):")
            for r in result["checks"]:
                if not r["pass"]:
                    print(f"    - {r['name']}: {r['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
