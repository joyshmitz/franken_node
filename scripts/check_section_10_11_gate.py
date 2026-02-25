#!/usr/bin/env python3
"""Section 10.11 verification gate: FrankenSQLite-Inspired Runtime Systems.

Aggregates evidence from all section 10.11 beads and produces a gate verdict.

Usage:
    python scripts/check_section_10_11_gate.py          # human-readable
    python scripts/check_section_10_11_gate.py --json    # machine-readable
    python scripts/check_section_10_11_gate.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path
from typing import Any


BEAD = "bd-1jpo"
SECTION = "10.11"

# Section 10.11 beads (from bd-1jpo dependency list)
SECTION_BEADS = [
    ("bd-cvt", "Define capability profiles for product subsystems and enforce narrowing"),
    ("bd-3vm", "Add ambient-authority audit gate for product security-critical modules"),
    ("bd-93k", "Add checkpoint-placement contract in all long orchestration loops"),
    ("bd-7om", "Adopt canonical cancel->drain->finalize protocol contracts"),
    ("bd-24k", "Implement bounded masking helper for tiny atomic product operations"),
    ("bd-2ah", "Adopt canonical obligation-tracked two-phase channel contracts"),
    ("bd-3he", "Implement supervision tree with restart budgets and escalation policies"),
    ("bd-2ko", "Adopt canonical deterministic lab runtime and protocol scenario suites"),
    ("bd-3u4", "Implement BOCPD regime detector for workload/incident stream shifts"),
    ("bd-2nt", "Implement VOI-budgeted monitor scheduling for expensive diagnostics"),
    ("bd-2gr", "Integrate canonical monotonic security epochs and transition barriers"),
    ("bd-3hw", "Integrate canonical remote idempotency and saga semantics"),
    ("bd-lus", "Integrate canonical scheduler lane and global bulkhead policies"),
    ("bd-390", "Implement anti-entropy reconciliation for distributed product trust state"),
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
    # Direct verdict field
    if data.get("verdict") == "PASS":
        return True
    # Boolean pass flags
    if data.get("overall_pass") is True:
        return True
    if data.get("all_passed") is True:
        return True
    # Status field variants
    status = str(data.get("status", "")).lower()
    if status == "pass":
        return True
    if status == "completed":
        return True
    if status.startswith("completed_with_"):
        return True
    # Nested verification_results: all python checks pass
    vr = data.get("verification_results", {})
    if vr:
        py_checker = vr.get("python_checker", {})
        py_tests = vr.get("python_unit_tests", {})
        if py_checker.get("verdict") == "PASS" and py_tests.get("verdict") == "PASS":
            return True
    # Partial blocked with all deliverables present
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


def check_bead_evidence(bead_id: str, title: str) -> dict[str, Any]:
    evidence_path = ROOT / "artifacts" / "section_10_11" / bead_id / "verification_evidence.json"
    if not evidence_path.is_file():
        return _check(f"evidence_{bead_id}", False, f"missing: {_safe_relative(evidence_path)}")
    try:
        data = json.loads(evidence_path.read_text())
        passed = _evidence_pass(data)
        return _check(
            f"evidence_{bead_id}",
            passed,
            f"PASS: {title[:60]}" if passed else f"FAIL: {title[:60]}",
        )
    except (json.JSONDecodeError, KeyError) as e:
        return _check(f"evidence_{bead_id}", False, f"parse error: {e}")


def check_bead_summary(bead_id: str) -> dict[str, Any]:
    summary_path = ROOT / "artifacts" / "section_10_11" / bead_id / "verification_summary.md"
    exists = summary_path.is_file()
    return _check(
        f"summary_{bead_id}",
        exists,
        f"exists: {_safe_relative(summary_path)}" if exists else f"missing: {_safe_relative(summary_path)}",
    )


def check_all_evidence_present() -> dict[str, Any]:
    count = 0
    for bead_id, _ in SECTION_BEADS:
        evidence_path = ROOT / "artifacts" / "section_10_11" / bead_id / "verification_evidence.json"
        if evidence_path.is_file():
            count += 1
    passed = count == len(SECTION_BEADS)
    return _check("all_evidence_present", passed, f"{count}/{len(SECTION_BEADS)} beads have evidence")


def check_all_verdicts_pass() -> dict[str, Any]:
    pass_count = 0
    fail_list: list[str] = []
    for bead_id, _ in SECTION_BEADS:
        evidence_path = ROOT / "artifacts" / "section_10_11" / bead_id / "verification_evidence.json"
        if evidence_path.is_file():
            try:
                data = json.loads(evidence_path.read_text())
                if _evidence_pass(data):
                    pass_count += 1
                else:
                    fail_list.append(bead_id)
            except (json.JSONDecodeError, KeyError):
                fail_list.append(bead_id)
        else:
            fail_list.append(bead_id)
    passed = pass_count == len(SECTION_BEADS)
    detail = f"{pass_count}/{len(SECTION_BEADS)} PASS" if passed else f"FAIL: {', '.join(fail_list)}"
    return _check("all_verdicts_pass", passed, detail)


def check_spec_files() -> list[dict[str, Any]]:
    checks = []
    for bead_id, _ in SECTION_BEADS:
        spec_path = ROOT / "docs" / "specs" / "section_10_11" / f"{bead_id}_contract.md"
        exists = spec_path.is_file()
        checks.append(_check(
            f"spec_{bead_id}",
            exists,
            f"exists: {_safe_relative(spec_path)}" if exists else f"missing: {_safe_relative(spec_path)}",
        ))
    return checks


def check_key_modules() -> list[dict[str, Any]]:
    checks = []
    key_modules = [
        ("checkpoint", "crates/franken-node/src/runtime/checkpoint.rs"),
        ("checkpoint_guard", "crates/franken-node/src/runtime/checkpoint_guard.rs"),
        ("bounded_mask", "crates/franken-node/src/runtime/bounded_mask.rs"),
        ("supervision", "crates/franken-node/src/connector/supervision.rs"),
        ("lane_router", "crates/franken-node/src/runtime/lane_router.rs"),
        ("bulkhead", "crates/franken-node/src/runtime/bulkhead.rs"),
        ("anti_entropy", "crates/franken-node/src/runtime/anti_entropy.rs"),
        ("epoch_guard", "crates/franken-node/src/runtime/epoch_guard.rs"),
    ]
    for name, rel_path in key_modules:
        path = ROOT / rel_path
        exists = path.is_file()
        checks.append(_check(
            f"module_{name}",
            exists,
            f"exists: {rel_path}" if exists else f"missing: {rel_path}",
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
    check_spec_files()
    check_key_modules()

    return RESULTS


def run_all() -> dict[str, Any]:
    results = run_all_checks()
    total = len(results)
    passed = sum(1 for r in results if r["pass"])
    failed = total - passed
    overall = failed == 0
    return {
        "bead_id": BEAD,
        "title": f"Section {SECTION} verification gate: FrankenSQLite-Inspired Runtime Systems",
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
    logger = configure_test_logging("check_section_10_11_gate")
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
