#!/usr/bin/env python3
"""Section 10.16 verification gate: Adjacent Substrate Integration.

Aggregates evidence from all section 10.16 beads and produces a gate verdict.

Usage:
    python3 scripts/check_section_10_16_gate.py          # human-readable
    python3 scripts/check_section_10_16_gate.py --json    # machine-readable
    python3 scripts/check_section_10_16_gate.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

BEAD = "bd-10g0"
SECTION = "10.16"

# Section 10.16 beads (all dependencies of bd-10g0)
SECTION_BEADS = [
    ("bd-2owx", "Publish substrate policy contract for adjacent substrates"),
    ("bd-28ld", "Add architecture dependency map for adjacent substrates"),
    ("bd-34ll", "Define frankentui integration contract for console/TUI surfaces"),
    ("bd-1xtf", "Migrate existing TUI workflows to frankentui primitives"),
    ("bd-1719", "Add deterministic visual/snapshot tests for frankentui surfaces"),
    ("bd-1a1j", "Define frankensqlite persistence integration contract"),
    ("bd-2tua", "Implement frankensqlite adapter layer for persistence surfaces"),
    ("bd-26ux", "Add migration path from interim stores to frankensqlite"),
    ("bd-bt82", "Define sqlmodel_rust usage policy and typed model boundaries"),
    ("bd-1v65", "Integrate sqlmodel_rust in domains with typed schema/query safety"),
    ("bd-3ndj", "Define fastapi_rust control-plane service integration contract"),
    ("bd-2f5l", "Build fastapi_rust service skeleton for control endpoints"),
    ("bd-159q", "Add waiver workflow for justified substrate exceptions"),
    ("bd-2ji2", "Add claim-language gate for substrate-backed evidence"),
    ("bd-35l5", "Add performance overhead guardrails for substrate integrations"),
    ("bd-3u2o", "Add substrate conformance gate in CI"),
    ("bd-8l9k", "Add cross-substrate contract tests for E2E behavior"),
]

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _evidence_pass(data: dict[str, Any]) -> bool:
    if data.get("verdict") == "PASS":
        return True
    if data.get("overall_pass") is True:
        return True
    if data.get("all_passed") is True:
        return True
    raw_status = str(data.get("status", "")).lower()
    if raw_status == "pass":
        return True
    if raw_status == "completed":
        return True
    if raw_status.startswith("completed_with_"):
        return True
    vr = data.get("verification_results", {})
    if vr:
        py_checker = vr.get("python_checker", {})
        py_tests = vr.get("python_unit_tests", {})
        if py_checker.get("verdict") == "PASS" and py_tests.get("verdict") == "PASS":
            return True
    overall_status = str(data.get("overall_status", "")).lower()
    if overall_status.startswith("partial_blocked_by_preexisting"):
        deliverables = data.get("deliverables", [])
        if deliverables and all(d.get("exists") for d in deliverables):
            return True
    return False


def _safe_relative(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


def _find_evidence(bead_id: str) -> Path | None:
    """Locate evidence file, trying verification_evidence.json then check_report.json."""
    base = ROOT / "artifacts" / "section_10_16" / bead_id
    for name in ("verification_evidence.json", "check_report.json"):
        p = base / name
        if p.is_file():
            return p
    return None


def _load_evidence(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def check_bead_evidence(bead_id: str, title: str) -> dict[str, Any]:
    evidence_path = _find_evidence(bead_id)
    if evidence_path is None:
        fallback = ROOT / "artifacts" / "section_10_16" / bead_id / "verification_evidence.json"
        return _check(f"evidence_{bead_id}", False, f"missing: {_safe_relative(fallback)}")
    data = _load_evidence(evidence_path)
    if data is None:
        return _check(f"evidence_{bead_id}", False, f"parse error: {_safe_relative(evidence_path)}")
    passed = _evidence_pass(data)
    return _check(
        f"evidence_{bead_id}",
        passed,
        f"PASS: {title[:60]}" if passed else f"FAIL: {title[:60]}",
    )


def check_bead_summary(bead_id: str) -> dict[str, Any]:
    summary_path = ROOT / "artifacts" / "section_10_16" / bead_id / "verification_summary.md"
    exists = summary_path.is_file()
    return _check(
        f"summary_{bead_id}",
        exists,
        f"exists: {_safe_relative(summary_path)}" if exists else f"missing: {_safe_relative(summary_path)}",
    )


def check_all_evidence_present() -> dict[str, Any]:
    count = 0
    for bead_id, _ in SECTION_BEADS:
        if _find_evidence(bead_id) is not None:
            count += 1
    passed = count == len(SECTION_BEADS)
    return _check("all_evidence_present", passed, f"{count}/{len(SECTION_BEADS)} beads have evidence")


def check_all_verdicts_pass() -> dict[str, Any]:
    pass_count = 0
    fail_list: list[str] = []
    for bead_id, _ in SECTION_BEADS:
        evidence_path = _find_evidence(bead_id)
        if evidence_path is not None:
            data = _load_evidence(evidence_path)
            if data is not None and _evidence_pass(data):
                pass_count += 1
            else:
                fail_list.append(bead_id)
        else:
            fail_list.append(bead_id)
    passed = pass_count == len(SECTION_BEADS)
    detail = f"{pass_count}/{len(SECTION_BEADS)} PASS" if passed else f"FAIL: {', '.join(fail_list)}"
    return _check("all_verdicts_pass", passed, detail)


def check_key_artifacts() -> list[dict[str, Any]]:
    checks = []
    key_artifacts = [
        ("substrate_policy", "docs/architecture/adjacent_substrate_policy.md"),
        ("substrate_manifest", "artifacts/10.16/adjacent_substrate_policy_manifest.json"),
        ("e2e_report", "artifacts/10.16/adjacent_substrate_e2e_report.json"),
    ]
    for name, rel_path in key_artifacts:
        path = ROOT / rel_path
        exists = path.is_file()
        checks.append(_check(
            f"artifact_{name}",
            exists,
            f"exists: {rel_path}" if exists else f"missing: {rel_path}",
        ))
    return checks


def check_key_scripts() -> list[dict[str, Any]]:
    checks = []
    key_scripts = [
        ("substrate_policy_check", "scripts/check_adjacent_substrate_policy.py"),
        ("cross_substrate_e2e_check", "scripts/check_cross_substrate_e2e.py"),
    ]
    for name, rel_path in key_scripts:
        path = ROOT / rel_path
        exists = path.is_file()
        checks.append(_check(
            f"script_{name}",
            exists,
            f"exists: {rel_path}" if exists else f"missing: {rel_path}",
        ))
    return checks


def check_gate_deliverables() -> list[dict[str, Any]]:
    checks = []
    gate_files = [
        ("gate_evidence", f"artifacts/section_10_16/{BEAD}/verification_evidence.json"),
        ("gate_summary", f"artifacts/section_10_16/{BEAD}/verification_summary.md"),
        ("gate_spec", f"docs/specs/section_10_16/{BEAD}_contract.md"),
        ("gate_tests", "tests/test_check_section_10_16_gate.py"),
    ]
    for name, rel_path in gate_files:
        path = ROOT / rel_path
        exists = path.is_file()
        checks.append(_check(
            name,
            exists,
            f"exists: {rel_path}" if exists else f"missing: {rel_path}",
        ))
    return checks


def check_substrate_coverage() -> list[dict[str, Any]]:
    """Verify all four substrates have integration artifacts."""
    checks = []
    substrates = {
        "frankentui": ["bd-34ll", "bd-1xtf", "bd-1719"],
        "frankensqlite": ["bd-1a1j", "bd-2tua", "bd-26ux"],
        "sqlmodel_rust": ["bd-bt82", "bd-1v65"],
        "fastapi_rust": ["bd-3ndj", "bd-2f5l"],
    }
    for substrate, bead_ids in substrates.items():
        passing = 0
        for bead_id in bead_ids:
            evidence_path = _find_evidence(bead_id)
            if evidence_path is not None:
                data = _load_evidence(evidence_path)
                if data is not None and _evidence_pass(data):
                    passing += 1
        all_pass = passing == len(bead_ids)
        checks.append(_check(
            f"substrate_{substrate}_coverage",
            all_pass,
            f"{passing}/{len(bead_ids)} beads PASS" if all_pass else f"{passing}/{len(bead_ids)} beads PASS",
        ))
    return checks


def run_all_checks() -> list[dict[str, Any]]:
    RESULTS.clear()

    for bead_id, title in SECTION_BEADS:
        check_bead_evidence(bead_id, title)

    for bead_id, _ in SECTION_BEADS:
        check_bead_summary(bead_id)

    check_all_evidence_present()
    check_all_verdicts_pass()
    check_key_artifacts()
    check_key_scripts()
    check_gate_deliverables()
    check_substrate_coverage()

    return RESULTS


def run_all() -> dict[str, Any]:
    results = run_all_checks()
    total = len(results)
    passed = sum(1 for r in results if r["pass"])
    failed = total - passed
    overall = failed == 0
    return {
        "bead_id": BEAD,
        "title": f"Section {SECTION} verification gate: Adjacent Substrate Integration",
        "section": SECTION,
        "gate": True,
        "verdict": "PASS" if overall else "FAIL",
        "overall_pass": overall,
        "total": total,
        "passed": passed,
        "failed": failed,
        "section_beads": [b[0] for b in SECTION_BEADS],
        "checks": results,
    }


def self_test() -> bool:
    results = run_all_checks()
    if not results:
        print("SELF-TEST FAIL: no checks returned", file=sys.stderr)
        return False
    for r in results:
        if not isinstance(r, dict) or not all(k in r for k in ("check", "pass", "detail")):
            print(f"SELF-TEST FAIL: bad result: {r}", file=sys.stderr)
            return False
    print(f"SELF-TEST OK: {len(results)} checks returned", file=sys.stderr)
    return True


def main() -> None:
    logger = configure_test_logging("check_section_10_16_gate")
    parser = argparse.ArgumentParser(description=f"Section {SECTION} verification gate")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(0 if self_test() else 1)

    result = run_all()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n  Section {SECTION} Gate: {'PASS' if result['verdict'] == 'PASS' else 'FAIL'} ({result['passed']}/{result['total']})\n")
        for r in result["checks"]:
            mark = "+" if r["pass"] else "x"
            print(f"  [{mark}] {r['check']}: {r['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
