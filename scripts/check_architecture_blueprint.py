#!/usr/bin/env python3
"""Verification script for bd-k25j: Architecture Blueprint.

Checks three-kernel architecture, 10 runtime invariants, 5 product planes,
3 control planes, 5 alignment contracts, event codes, and invariants.

Usage:
    python scripts/check_architecture_blueprint.py [--json]
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
        "blueprint_doc": "docs/architecture/blueprint.md",
        "spec_contract": "docs/specs/section_8/bd-k25j_contract.md",
    }
    ok = 0
    for label, rel in files.items():
        if _check(f"file_exists:{label}", (ROOT / rel).is_file(), rel):
            ok += 1
    return ok


def check_three_kernels() -> int:
    doc = ROOT / "docs/architecture/blueprint.md"
    if not doc.is_file():
        return 0
    text = doc.read_text().lower()
    kernels = [
        ("execution", "franken_engine"),
        ("correctness", "asupersync"),
        ("product", "franken_node"),
    ]
    ok = 0
    for label, name in kernels:
        if _check(f"kernel:{label}", label in text and name in text, f"{label}: {name}"):
            ok += 1
    return ok


def check_product_planes() -> int:
    doc = ROOT / "docs/architecture/blueprint.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    planes = {
        "PP-01": "Compatibility",
        "PP-02": "Migration",
        "PP-03": "Trust",
        "PP-04": "Ecosystem",
        "PP-05": "Operations",
    }
    ok = 0
    for pid, name in planes.items():
        if _check(f"product_plane:{pid}", pid in text and name in text, f"{pid}: {name}"):
            ok += 1
    return ok


def check_control_planes() -> int:
    doc = ROOT / "docs/architecture/blueprint.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    planes = {
        "CP-01": "Release",
        "CP-02": "Incident",
        "CP-03": "Economics",
    }
    ok = 0
    for pid, name in planes.items():
        if _check(f"control_plane:{pid}", pid in text and name in text, f"{pid}: {name}"):
            ok += 1
    return ok


def check_ten_invariants() -> int:
    doc = ROOT / "docs/architecture/blueprint.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    invariants = {
        "HRI-01": "Cx-first",
        "HRI-02": "Region",
        "HRI-03": "Cancellation",
        "HRI-04": "Two-phase",
        "HRI-05": "Scheduler lane",
        "HRI-06": "Remote effects",
        "HRI-07": "Epoch",
        "HRI-08": "Evidence",
        "HRI-09": "Deterministic",
        "HRI-10": "No ambient",
    }
    ok = 0
    for hid, kw in invariants.items():
        if _check(f"hri:{hid}", hid in text and kw.lower() in text.lower(), f"{hid}: {kw}"):
            ok += 1
    return ok


def check_alignment_contracts() -> int:
    doc = ROOT / "docs/architecture/blueprint.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    contracts = {
        "AC-01": "Scope",
        "AC-02": "Terminology",
        "AC-03": "Dual-Oracle",
        "AC-04": "Path",
        "AC-05": "KPI",
    }
    ok = 0
    for cid, kw in contracts.items():
        if _check(f"alignment:{cid}", cid in text and kw in text, f"{cid}: {kw}"):
            ok += 1
    return ok


def check_boundary_rules() -> int:
    doc = ROOT / "docs/architecture/blueprint.md"
    if not doc.is_file():
        return 0
    text = doc.read_text().lower()
    keywords = ["boundary rule", "never reaches into", "orchestrates and verifies"]
    ok = 0
    for kw in keywords:
        if _check(f"boundary:{kw[:20]}", kw in text, f"boundary: {kw}"):
            ok += 1
    return ok


def check_event_codes() -> int:
    doc = ROOT / "docs/architecture/blueprint.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    codes = ["ARC-001", "ARC-002", "ARC-003", "ARC-004"]
    ok = 0
    for code in codes:
        if _check(f"event_code:{code}", code in text, code):
            ok += 1
    return ok


def check_meta_invariants() -> int:
    doc = ROOT / "docs/architecture/blueprint.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    invariants = ["INV-ARC-KERNEL", "INV-ARC-HRI", "INV-ARC-ALIGN", "INV-ARC-PLANE"]
    ok = 0
    for inv in invariants:
        if _check(f"invariant:{inv}", inv in text, inv):
            ok += 1
    return ok


def check_required_sections() -> int:
    doc = ROOT / "docs/architecture/blueprint.md"
    if not doc.is_file():
        return 0
    text = doc.read_text()
    headings = [
        "Repository",
        "Product Planes",
        "Control Planes",
        "Three-Kernel",
        "Runtime Invariants",
        "Alignment Contracts",
    ]
    ok = 0
    for h in headings:
        if _check(f"section:{h}", h in text, f"section: {h}"):
            ok += 1
    return ok


def check_spec_contract() -> int:
    spec = ROOT / "docs/specs/section_8/bd-k25j_contract.md"
    if not spec.is_file():
        return 0
    text = spec.read_text()
    keywords = ["bd-k25j", "HRI-01", "HRI-10", "AC-01", "PP-01", "ARC-001", "INV-ARC"]
    ok = 0
    for kw in keywords:
        if _check(f"spec:{kw}", kw in text, f"spec: {kw}"):
            ok += 1
    return ok


def run_all() -> dict:
    RESULTS.clear()
    check_files_exist()
    check_three_kernels()
    check_product_planes()
    check_control_planes()
    check_ten_invariants()
    check_alignment_contracts()
    check_boundary_rules()
    check_event_codes()
    check_meta_invariants()
    check_required_sections()
    check_spec_contract()

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "bead_id": "bd-k25j",
        "title": "Architecture Blueprint",
        "section": "8",
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": RESULTS,
    }


def self_test():
    assert callable(check_ten_invariants)
    assert callable(check_alignment_contracts)
    result = run_all()
    assert "verdict" in result
    assert result["total"] > 0
    print("self_test: OK")


def main():
    logger = configure_test_logging("check_architecture_blueprint")
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-k25j Architecture Blueprint: {result['verdict']}")
        print(f"  Checks: {result['passed']}/{result['total']}")
        if result["failed"] > 0:
            print(f"  FAILED ({result['failed']}):")
            for r in result["checks"]:
                if not r["pass"]:
                    print(f"    - {r['name']}: {r['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
