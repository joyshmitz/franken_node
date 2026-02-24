#!/usr/bin/env python3
"""Verification script for bd-22e7: Method Stack Compliance.

Checks that all four mandatory execution disciplines are documented,
the compliance matrix is valid, and all required sections/artifacts
are properly defined.

Usage:
    python scripts/check_method_stack_compliance.py [--json]
"""

import json
import os
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
    """Verify all required artifacts exist."""
    files = {
        "method_stack_doc": "docs/methodology/method_stack_compliance.md",
        "compliance_matrix": "docs/methodology/compliance_matrix.json",
        "spec_contract": "docs/specs/section_5/bd-22e7_contract.md",
    }
    ok = 0
    for label, rel in files.items():
        p = ROOT / rel
        if _check(f"file_exists:{label}", p.is_file(), str(rel)):
            ok += 1
    return ok


def check_method_stacks_documented() -> int:
    """Verify all 4 method stacks are documented in the reference guide."""
    doc = ROOT / "docs/methodology/method_stack_compliance.md"
    if not doc.is_file():
        _check("stacks_documented:file_missing", False, "method_stack_compliance.md not found")
        return 0
    text = doc.read_text()
    stacks = {
        "MS-01": "extreme-software-optimization",
        "MS-02": "alien-artifact-coding",
        "MS-03": "alien-graveyard",
        "MS-04": "porting-to-rust",
    }
    ok = 0
    for sid, name in stacks.items():
        if _check(f"stack_documented:{sid}", sid in text and name in text, f"{sid}: {name}"):
            ok += 1
    return ok


def check_stack_domains() -> int:
    """Verify each stack has its domain documented."""
    doc = ROOT / "docs/methodology/method_stack_compliance.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    domains = {
        "MS-01": "Performance",
        "MS-02": "Decision",
        "MS-03": "Primitive",
        "MS-04": "Compatibility",
    }
    ok = 0
    for sid, keyword in domains.items():
        if _check(f"stack_domain:{sid}", keyword.lower() in text.lower(), f"{sid} domain: {keyword}"):
            ok += 1
    return ok


def check_required_artifacts_per_stack() -> int:
    """Verify each stack lists its required artifacts."""
    doc = ROOT / "docs/methodology/method_stack_compliance.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    artifact_keywords = {
        "MS-01": ["benchmark", "flamegraph", "compatibility"],
        "MS-02": ["decision rationale", "policy receipt"],
        "MS-03": ["EV analysis", "fallback contract", "degraded"],
        "MS-04": ["spec reference", "fixture", "parity"],
    }
    ok = 0
    for sid, keywords in artifact_keywords.items():
        for kw in keywords:
            if _check(f"artifact_keyword:{sid}:{kw}", kw.lower() in text.lower(), f"{sid} artifact: {kw}"):
                ok += 1
    return ok


def check_compliance_checks() -> int:
    """Verify compliance check codes are defined."""
    doc = ROOT / "docs/methodology/method_stack_compliance.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    codes = ["MSC-001:MS-01", "MSC-001:MS-02", "MSC-001:MS-03", "MSC-001:MS-04"]
    ok = 0
    for code in codes:
        if _check(f"compliance_check:{code}", code in text, code):
            ok += 1
    return ok


def check_event_codes() -> int:
    """Verify all event codes are documented."""
    doc = ROOT / "docs/methodology/method_stack_compliance.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    codes = {
        "MSC-001": "compliance check passed",
        "MSC-002": "violation",
        "MSC-003": "citation found",
        "MSC-004": "missing required artifact",
    }
    ok = 0
    for code, desc_kw in codes.items():
        if _check(f"event_code:{code}", code in text, f"{code}: {desc_kw}"):
            ok += 1
    return ok


def check_invariants() -> int:
    """Verify all invariants are documented."""
    doc = ROOT / "docs/methodology/method_stack_compliance.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    invariants = [
        "INV-MSC-CITED",
        "INV-MSC-ARTIFACT",
        "INV-MSC-FORMAL",
        "INV-MSC-SPEC-FIRST",
    ]
    ok = 0
    for inv in invariants:
        if _check(f"invariant:{inv}", inv in text, inv):
            ok += 1
    return ok


def check_compliance_matrix_json() -> int:
    """Verify the compliance matrix JSON is valid and complete."""
    matrix_path = ROOT / "docs/methodology/compliance_matrix.json"
    if not matrix_path.is_file():
        _check("matrix:file_missing", False, "compliance_matrix.json not found")
        return 0

    ok = 0
    try:
        data = json.loads(matrix_path.read_text())
    except json.JSONDecodeError as e:
        _check("matrix:valid_json", False, str(e))
        return 0

    if _check("matrix:valid_json", True, "JSON parses"):
        ok += 1

    # schema_version
    if _check("matrix:schema_version", data.get("schema_version") == "1.0", f"got {data.get('schema_version')}"):
        ok += 1

    # bead_id
    if _check("matrix:bead_id", data.get("bead_id") == "bd-22e7", f"got {data.get('bead_id')}"):
        ok += 1

    # method_stacks has 4 entries
    stacks = data.get("method_stacks", {})
    if _check("matrix:four_stacks", len(stacks) == 4, f"got {len(stacks)}"):
        ok += 1

    # Each stack has required fields
    for sid in ["MS-01", "MS-02", "MS-03", "MS-04"]:
        s = stacks.get(sid, {})
        has_name = "name" in s
        has_domain = "domain" in s
        has_artifacts = "required_artifacts" in s
        has_check = "compliance_check" in s
        if _check(f"matrix:stack_fields:{sid}", has_name and has_domain and has_artifacts and has_check, sid):
            ok += 1

    # section_requirements has entries
    sections = data.get("section_requirements", {})
    if _check("matrix:has_sections", len(sections) >= 10, f"got {len(sections)} sections"):
        ok += 1

    # Each section requirement references valid stack IDs
    valid_ids = {"MS-01", "MS-02", "MS-03", "MS-04"}
    all_valid = True
    for sec, stack_list in sections.items():
        for sid in stack_list:
            if sid not in valid_ids:
                all_valid = False
    if _check("matrix:valid_stack_refs", all_valid, "all section refs use valid stack IDs"):
        ok += 1

    # event_codes has 4 entries
    events = data.get("event_codes", {})
    if _check("matrix:four_events", len(events) == 4, f"got {len(events)}"):
        ok += 1

    # Specific sections map correctly
    section_map = {
        "10.2": ["MS-04"],
        "10.3": ["MS-04"],
        "10.5": ["MS-02"],
        "10.6": ["MS-01"],
        "10.7": ["MS-04"],
    }
    for sec, expected in section_map.items():
        actual = sections.get(sec, [])
        if _check(f"matrix:section_map:{sec}", sorted(actual) == sorted(expected),
                  f"expected {expected}, got {actual}"):
            ok += 1

    return ok


def check_compliance_table() -> int:
    """Verify the compliance matrix table in the doc."""
    doc = ROOT / "docs/methodology/method_stack_compliance.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    ok = 0

    # Table header
    if _check("table:header", "MS-01" in text and "MS-02" in text and "MS-03" in text and "MS-04" in text,
              "compliance matrix table header"):
        ok += 1

    # Key section rows
    section_rows = ["10.2", "10.3", "10.5", "10.6", "10.7", "10.14", "10.15", "10.17"]
    for sec in section_rows:
        if _check(f"table:section_row:{sec}", f"| {sec}" in text or f"|{sec}" in text, f"section {sec} in table"):
            ok += 1

    # REQUIRED keyword appears
    if _check("table:required_keyword", "REQUIRED" in text, "REQUIRED appears in table"):
        ok += 1

    return ok


def check_pr_checklist() -> int:
    """Verify PR compliance checklist is documented."""
    doc = ROOT / "docs/methodology/method_stack_compliance.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    ok = 0

    keywords = ["PR Compliance", "Stack(s)", "Artifacts", "Verification"]
    for kw in keywords:
        if _check(f"pr_checklist:{kw}", kw in text, f"PR checklist: {kw}"):
            ok += 1
    return ok


def check_spec_contract() -> int:
    """Verify the spec contract has required content."""
    spec = ROOT / "docs/specs/section_5/bd-22e7_contract.md"
    if not spec.is_file():
        _check("spec:file_missing", False, "spec contract not found")
        return 0
    text = spec.read_text()
    ok = 0

    keywords = [
        "bd-22e7",
        "Method Stack",
        "MS-01",
        "MS-02",
        "MS-03",
        "MS-04",
        "MSC-001",
        "INV-MSC",
    ]
    for kw in keywords:
        if _check(f"spec:{kw}", kw in text, f"spec contract: {kw}"):
            ok += 1
    return ok


def run_all() -> dict:
    """Run all checks and return summary."""
    RESULTS.clear()
    check_files_exist()
    check_method_stacks_documented()
    check_stack_domains()
    check_required_artifacts_per_stack()
    check_compliance_checks()
    check_event_codes()
    check_invariants()
    check_compliance_matrix_json()
    check_compliance_table()
    check_pr_checklist()
    check_spec_contract()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "bead_id": "bd-22e7",
        "title": "Method Stack Compliance — 4 execution disciplines",
        "section": "5",
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": RESULTS,
    }


def self_test():
    """Minimal self-test for the verification script."""
    assert callable(check_files_exist)
    assert callable(check_method_stacks_documented)
    assert callable(check_compliance_matrix_json)
    assert callable(run_all)
    result = run_all()
    assert "verdict" in result
    assert "checks" in result
    assert result["total"] > 0
    print("self_test: OK")


def main():
    logger = configure_test_logging("check_method_stack_compliance")
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-22e7 Method Stack Compliance: {result['verdict']}")
        print(f"  Checks: {result['passed']}/{result['total']}")
        if result["failed"] > 0:
            print(f"  FAILED ({result['failed']}):")
            for r in result["checks"]:
                if not r["pass"]:
                    print(f"    - {r['name']}: {r['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
