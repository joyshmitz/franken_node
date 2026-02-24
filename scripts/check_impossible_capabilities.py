#!/usr/bin/env python3
"""Verification script for bd-2hrg: Impossible-by-Default Capability Index.

Checks that all 10 capabilities, category-creation tests, quantitative targets,
event codes, and invariants are documented.

Usage:
    python scripts/check_impossible_capabilities.py [--json]
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
        "capabilities_doc": "docs/doctrine/impossible_by_default_capabilities.md",
        "spec_contract": "docs/specs/section_3_2/bd-2hrg_contract.md",
    }
    ok = 0
    for label, rel in files.items():
        if _check(f"file_exists:{label}", (ROOT / rel).is_file(), rel):
            ok += 1
    return ok


def check_ten_capabilities() -> int:
    doc = ROOT / "docs/doctrine/impossible_by_default_capabilities.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    capabilities = {
        "IBD-01": "compatibility",
        "IBD-02": "migration audit",
        "IBD-03": "revocation",
        "IBD-04": "deterministic",
        "IBD-05": "quarantine",
        "IBD-06": "trust card",
        "IBD-07": "lockstep oracle",
        "IBD-08": "expected-loss",
        "IBD-09": "reputation graph",
        "IBD-10": "verifier toolkit",
    }
    ok = 0
    for cid, kw in capabilities.items():
        if _check(f"capability:{cid}", cid in text and kw.lower() in text.lower(), f"{cid}: {kw}"):
            ok += 1
    return ok


def check_impossibility_rationale() -> int:
    doc = ROOT / "docs/doctrine/impossible_by_default_capabilities.md"
    if not doc.is_file():
        return 0
    text = doc.read_text().lower()
    ok = 0
    count = text.count("why impossible")
    if _check("impossibility:rationale_count", count >= 10, f"found {count} 'why impossible' sections"):
        ok += 1
    return ok


def check_owner_tracks() -> int:
    doc = ROOT / "docs/doctrine/impossible_by_default_capabilities.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    tracks = ["10.2", "10.3", "10.4", "10.5", "10.8", "10.10", "10.12", "10.13", "10.14", "10.17", "10.19", "10.20", "10.21"]
    ok = 0
    for t in tracks:
        if _check(f"owner_track:{t}", t in text, f"track: {t}"):
            ok += 1
    return ok


def check_category_tests() -> int:
    doc = ROOT / "docs/doctrine/impossible_by_default_capabilities.md"
    if not doc.is_file():
        return 0
    text = doc.read_text().lower()
    tests = ["uniqueness", "verifiability", "migration"]
    ok = 0
    for t in tests:
        if _check(f"category_test:{t}", t in text, f"test: {t}"):
            ok += 1
    return ok


def check_quantitative_targets() -> int:
    doc = ROOT / "docs/doctrine/impossible_by_default_capabilities.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    targets = {
        "QT-01": "95%",
        "QT-02": "3x",
        "QT-03": "10x",
        "QT-04": "100%",
        "QT-05": "3",
    }
    ok = 0
    for tid, val in targets.items():
        if _check(f"target:{tid}", tid in text and val in text, f"{tid}: {val}"):
            ok += 1
    return ok


def check_event_codes() -> int:
    doc = ROOT / "docs/doctrine/impossible_by_default_capabilities.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    codes = ["IBD-001", "IBD-002", "IBD-003", "IBD-004"]
    ok = 0
    for code in codes:
        if _check(f"event_code:{code}", code in text, code):
            ok += 1
    return ok


def check_invariants() -> int:
    doc = ROOT / "docs/doctrine/impossible_by_default_capabilities.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    invariants = [
        "INV-IBD-MAPPED",
        "INV-IBD-EVIDENCE",
        "INV-IBD-UNIQUE",
        "INV-IBD-COMPLETE",
    ]
    ok = 0
    for inv in invariants:
        if _check(f"invariant:{inv}", inv in text, inv):
            ok += 1
    return ok


def check_required_sections() -> int:
    doc = ROOT / "docs/doctrine/impossible_by_default_capabilities.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    headings = [
        "10 Capabilities",
        "Category-Creation Test",
        "Quantitative Targets",
        "Event Codes",
        "Invariants",
    ]
    ok = 0
    for h in headings:
        if _check(f"section:{h}", h in text, f"section: {h}"):
            ok += 1
    return ok


def check_spec_contract() -> int:
    spec = ROOT / "docs/specs/section_3_2/bd-2hrg_contract.md"
    if not spec.is_file():
        return 0
    text = spec.read_text()
    keywords = ["bd-2hrg", "IBD-01", "IBD-10", "QT-01", "IBD-001", "INV-IBD"]
    ok = 0
    for kw in keywords:
        if _check(f"spec:{kw}", kw in text, f"spec: {kw}"):
            ok += 1
    return ok


def run_all() -> dict:
    RESULTS.clear()
    check_files_exist()
    check_ten_capabilities()
    check_impossibility_rationale()
    check_owner_tracks()
    check_category_tests()
    check_quantitative_targets()
    check_event_codes()
    check_invariants()
    check_required_sections()
    check_spec_contract()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "bead_id": "bd-2hrg",
        "title": "Impossible-by-Default Capability Index",
        "section": "3.2",
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": RESULTS,
    }


def self_test():
    assert callable(check_ten_capabilities)
    assert callable(check_category_tests)
    result = run_all()
    assert "verdict" in result
    assert result["total"] > 0
    print("self_test: OK")


def main():
    logger = configure_test_logging("check_impossible_capabilities")
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-2hrg Impossible Capabilities: {result['verdict']}")
        print(f"  Checks: {result['passed']}/{result['total']}")
        if result["failed"] > 0:
            print(f"  FAILED ({result['failed']}):")
            for r in result["checks"]:
                if not r["pass"]:
                    print(f"    - {r['name']}: {r['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
