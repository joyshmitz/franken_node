#!/usr/bin/env python3
"""Verification script for bd-3hyk: Strategic Foundations.

Checks that mission, thesis, category-creation doctrine, build strategy,
disruptive floor targets, event codes, and invariants are documented.

Usage:
    python scripts/check_strategic_foundations.py [--json]
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
        "foundations_doc": "docs/doctrine/strategic_foundations.md",
        "spec_contract": "docs/specs/section_1_3/bd-3hyk_contract.md",
    }
    ok = 0
    for label, rel in files.items():
        if _check(f"file_exists:{label}", (ROOT / rel).is_file(), rel):
            ok += 1
    return ok


def check_three_kernel() -> int:
    doc = ROOT / "docs/doctrine/strategic_foundations.md"
    if not doc.is_file():
        return 0
    text = doc.read_text().lower()
    kernels = ["franken_engine", "asupersync", "franken_node"]
    ok = 0
    for k in kernels:
        if _check(f"kernel:{k}", k in text, f"kernel: {k}"):
            ok += 1
    return ok


def check_four_pillars() -> int:
    doc = ROOT / "docs/doctrine/strategic_foundations.md"
    if not doc.is_file():
        return 0
    text = doc.read_text().lower()
    pillars = ["ergonomics", "security", "explainability", "operations"]
    ok = 0
    for p in pillars:
        if _check(f"pillar:{p}", p in text, f"pillar: {p}"):
            ok += 1
    return ok


def check_core_proposition() -> int:
    doc = ROOT / "docs/doctrine/strategic_foundations.md"
    if not doc.is_file():
        return 0
    text = doc.read_text().lower()
    props = ["compatibility", "trust-native", "migration velocity"]
    ok = 0
    for p in props:
        if _check(f"proposition:{p}", p in text, f"proposition: {p}"):
            ok += 1
    return ok


def check_disruptive_floor() -> int:
    doc = ROOT / "docs/doctrine/strategic_foundations.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    targets = {
        "DF-01": "95%",
        "DF-02": "3x",
        "DF-03": "10x",
        "DF-04": "automation",
        "DF-05": "100%",
        "DF-06": "3 impossible",
    }
    ok = 0
    for tid, kw in targets.items():
        found = tid in text and kw.lower() in text.lower()
        if _check(f"disruptive_floor:{tid}", found, f"{tid}: {kw}"):
            ok += 1
    return ok


def check_category_doctrine() -> int:
    doc = ROOT / "docs/doctrine/strategic_foundations.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    rules = ["CCD-01", "CCD-02", "CCD-03", "CCD-04", "CCD-05"]
    ok = 0
    for r in rules:
        if _check(f"doctrine_rule:{r}", r in text, r):
            ok += 1
    return ok


def check_build_strategy() -> int:
    doc = ROOT / "docs/doctrine/strategic_foundations.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    principles = ["BST-01", "BST-02", "BST-03", "BST-04"]
    ok = 0
    for p in principles:
        if _check(f"build_strategy:{p}", p in text, p):
            ok += 1
    return ok


def check_build_strategy_keywords() -> int:
    doc = ROOT / "docs/doctrine/strategic_foundations.md"
    if not doc.is_file():
        return 0
    text = doc.read_text().lower()
    keywords = ["spec-first", "essence extraction", "oracle", "not architecture"]
    ok = 0
    for kw in keywords:
        if _check(f"strategy_keyword:{kw}", kw in text, f"keyword: {kw}"):
            ok += 1
    return ok


def check_anti_clone_decision() -> int:
    doc = ROOT / "docs/doctrine/strategic_foundations.md"
    if not doc.is_file():
        return 0
    text = doc.read_text().lower()
    ok = 0
    if _check("anti_clone:decision", "not begin with a full clean-room" in text or "not a" in text and "clone" in text, "anti-clone decision"):
        ok += 1
    return ok


def check_event_codes() -> int:
    doc = ROOT / "docs/doctrine/strategic_foundations.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    codes = ["STR-001", "STR-002", "STR-003", "STR-004"]
    ok = 0
    for code in codes:
        if _check(f"event_code:{code}", code in text, code):
            ok += 1
    return ok


def check_invariants() -> int:
    doc = ROOT / "docs/doctrine/strategic_foundations.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    invariants = [
        "INV-STR-THESIS",
        "INV-STR-FLOOR",
        "INV-STR-DOCTRINE",
        "INV-STR-STRATEGY",
    ]
    ok = 0
    for inv in invariants:
        if _check(f"invariant:{inv}", inv in text, inv):
            ok += 1
    return ok


def check_required_sections() -> int:
    doc = ROOT / "docs/doctrine/strategic_foundations.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    headings = [
        "Background and Role",
        "Core Thesis",
        "Strategic Objective",
        "Category-Creation Doctrine",
        "Build Strategy",
        "Disruptive Floor",
    ]
    ok = 0
    for h in headings:
        if _check(f"section:{h}", h in text, f"section: {h}"):
            ok += 1
    return ok


def check_spec_contract() -> int:
    spec = ROOT / "docs/specs/section_1_3/bd-3hyk_contract.md"
    if not spec.is_file():
        return 0
    text = spec.read_text()
    keywords = ["bd-3hyk", "DF-01", "CCD-01", "BST-01", "STR-001", "INV-STR"]
    ok = 0
    for kw in keywords:
        if _check(f"spec:{kw}", kw in text, f"spec: {kw}"):
            ok += 1
    return ok


def run_all() -> dict:
    RESULTS.clear()
    check_files_exist()
    check_three_kernel()
    check_four_pillars()
    check_core_proposition()
    check_disruptive_floor()
    check_category_doctrine()
    check_build_strategy()
    check_build_strategy_keywords()
    check_anti_clone_decision()
    check_event_codes()
    check_invariants()
    check_required_sections()
    check_spec_contract()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "bead_id": "bd-3hyk",
        "title": "Strategic Foundations — mission, thesis, category-creation",
        "section": "1-3",
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": RESULTS,
    }


def self_test():
    assert callable(check_disruptive_floor)
    assert callable(check_category_doctrine)
    result = run_all()
    assert "verdict" in result
    assert result["total"] > 0
    print("self_test: OK")


def main():
    logger = configure_test_logging("check_strategic_foundations")
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-3hyk Strategic Foundations: {result['verdict']}")
        print(f"  Checks: {result['passed']}/{result['total']}")
        if result["failed"] > 0:
            print(f"  FAILED ({result['failed']}):")
            for r in result["checks"]:
                if not r["pass"]:
                    print(f"    - {r['name']}: {r['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
