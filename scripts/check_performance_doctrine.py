#!/usr/bin/env python3
"""Verification script for bd-2vl5: Performance and Developer Velocity Doctrine.

Checks that all core principles, optimization levers, performance artifacts,
event codes, and invariants are documented.

Usage:
    python scripts/check_performance_doctrine.py [--json]
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

RESULTS: list[dict] = []


def _check(name: str, passed: bool, detail: str = "") -> bool:
    RESULTS.append({"name": name, "pass": passed, "detail": detail})
    return passed


def check_files_exist() -> int:
    files = {
        "doctrine_doc": "docs/doctrine/performance_and_velocity.md",
        "spec_contract": "docs/specs/section_7/bd-2vl5_contract.md",
    }
    ok = 0
    for label, rel in files.items():
        if _check(f"file_exists:{label}", (ROOT / rel).is_file(), rel):
            ok += 1
    return ok


def check_core_principles() -> int:
    doc = ROOT / "docs/doctrine/performance_and_velocity.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    principles = {
        "PRF-01": "startup",
        "PRF-02": "p99",
        "PRF-03": "security",
        "PRF-04": "migration",
    }
    ok = 0
    for pid, kw in principles.items():
        if _check(f"principle:{pid}", pid in text and kw.lower() in text.lower(), f"{pid}: {kw}"):
            ok += 1
    return ok


def check_quantitative_targets() -> int:
    doc = ROOT / "docs/doctrine/performance_and_velocity.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    targets = [
        ("cold_start", "100ms"),
        ("security_overhead", "5%"),
        ("diff_generation", "500ms"),
    ]
    ok = 0
    for label, val in targets:
        if _check(f"target:{label}", val in text, f"target: {val}"):
            ok += 1
    return ok


def check_optimization_levers() -> int:
    doc = ROOT / "docs/doctrine/performance_and_velocity.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    levers = {
        "LEV-01": "compatibility cache",
        "LEV-02": "lockstep",
        "LEV-03": "zero-copy",
        "LEV-04": "batch policy",
        "LEV-05": "multi-lane scheduler",
    }
    ok = 0
    for lid, kw in levers.items():
        if _check(f"lever:{lid}", lid in text and kw.lower() in text.lower(), f"{lid}: {kw}"):
            ok += 1
    return ok


def check_lever_details() -> int:
    doc = ROOT / "docs/doctrine/performance_and_velocity.md"
    if not doc.is_file():
        return 0
    text = doc.read_text().lower()
    details = ["expected impact", "risk", "owner track"]
    ok = 0
    for d in details:
        if _check(f"lever_detail:{d}", d in text, f"lever detail: {d}"):
            ok += 1
    return ok


def check_required_artifacts() -> int:
    doc = ROOT / "docs/doctrine/performance_and_velocity.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    artifacts = {
        "ART-01": "baseline",
        "ART-02": "profile",
        "ART-03": "before/after",
        "ART-04": "compatibility correctness",
        "ART-05": "tail-latency",
    }
    ok = 0
    for aid, kw in artifacts.items():
        if _check(f"artifact:{aid}", aid in text and kw.lower() in text.lower(), f"{aid}: {kw}"):
            ok += 1
    return ok


def check_artifact_contents() -> int:
    doc = ROOT / "docs/doctrine/performance_and_velocity.md"
    if not doc.is_file():
        return 0
    text = doc.read_text().lower()
    keywords = [
        "flamegraph",
        "p50",
        "p95",
        "p99",
        "throughput",
        "memory",
        "cold-start",
        "reproducible",
    ]
    ok = 0
    for kw in keywords:
        if _check(f"artifact_content:{kw}", kw in text, f"artifact content: {kw}"):
            ok += 1
    return ok


def check_implementation_mapping() -> int:
    doc = ROOT / "docs/doctrine/performance_and_velocity.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    tracks = ["10.6", "10.15", "10.18"]
    ok = 0
    for t in tracks:
        if _check(f"impl_mapping:{t}", t in text, f"track: {t}"):
            ok += 1
    return ok


def check_event_codes() -> int:
    doc = ROOT / "docs/doctrine/performance_and_velocity.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    codes = ["PRF-001", "PRF-002", "PRF-003", "PRF-004", "PRF-005"]
    ok = 0
    for code in codes:
        if _check(f"event_code:{code}", code in text, code):
            ok += 1
    return ok


def check_invariants() -> int:
    doc = ROOT / "docs/doctrine/performance_and_velocity.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    invariants = [
        "INV-PRF-PRINCIPLES",
        "INV-PRF-ARTIFACTS",
        "INV-PRF-PROFILED",
        "INV-PRF-COMPAT",
    ]
    ok = 0
    for inv in invariants:
        if _check(f"invariant:{inv}", inv in text, inv):
            ok += 1
    return ok


def check_required_sections() -> int:
    doc = ROOT / "docs/doctrine/performance_and_velocity.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    headings = [
        "Core Principles",
        "Optimization Levers",
        "Required Performance Artifacts",
        "Implementation Mapping",
        "Event Codes",
        "Invariants",
    ]
    ok = 0
    for h in headings:
        if _check(f"section:{h}", h in text, f"section: {h}"):
            ok += 1
    return ok


def check_spec_contract() -> int:
    spec = ROOT / "docs/specs/section_7/bd-2vl5_contract.md"
    if not spec.is_file():
        return 0
    text = spec.read_text()
    keywords = ["bd-2vl5", "PRF-01", "LEV-01", "ART-01", "PRF-001", "INV-PRF"]
    ok = 0
    for kw in keywords:
        if _check(f"spec:{kw}", kw in text, f"spec: {kw}"):
            ok += 1
    return ok


def run_all() -> dict:
    RESULTS.clear()
    check_files_exist()
    check_core_principles()
    check_quantitative_targets()
    check_optimization_levers()
    check_lever_details()
    check_required_artifacts()
    check_artifact_contents()
    check_implementation_mapping()
    check_event_codes()
    check_invariants()
    check_required_sections()
    check_spec_contract()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "bead_id": "bd-2vl5",
        "title": "Performance and Developer Velocity Doctrine",
        "section": "7",
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": RESULTS,
    }


def self_test():
    assert callable(check_core_principles)
    assert callable(check_optimization_levers)
    result = run_all()
    assert "verdict" in result
    assert result["total"] > 0
    print("self_test: OK")


def main():
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-2vl5 Performance Doctrine: {result['verdict']}")
        print(f"  Checks: {result['passed']}/{result['total']}")
        if result["failed"] > 0:
            print(f"  FAILED ({result['failed']}):")
            for r in result["checks"]:
                if not r["pass"]:
                    print(f"    - {r['name']}: {r['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
