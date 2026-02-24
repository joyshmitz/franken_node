#!/usr/bin/env python3
"""Verification script for bd-3u6o: Canonical virtual transport fault harness
for distributed control protocols.

Checks that the adoption documentation, report artifact, spec contract,
upstream harness, and invariants are present and consistent.

Usage:
    python3 scripts/check_control_transport_faults.py            # human-readable
    python3 scripts/check_control_transport_faults.py --json      # machine-readable
    python3 scripts/check_control_transport_faults.py --self-test  # smoke-test
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

DOC = ROOT / "docs" / "testing" / "control_virtual_transport_faults.md"
REPORT = ROOT / "artifacts" / "10.15" / "control_fault_harness_summary.json"
SPEC = ROOT / "docs" / "specs" / "section_10_15" / "bd-3u6o_contract.md"
UPSTREAM_HARNESS = (
    ROOT / "crates" / "franken-node" / "src" / "remote" / "virtual_transport_faults.rs"
)
UNIT_TESTS = ROOT / "tests" / "test_check_control_transport_faults.py"
EVIDENCE = (
    ROOT / "artifacts" / "section_10_15" / "bd-3u6o" / "verification_evidence.json"
)
SUMMARY = (
    ROOT / "artifacts" / "section_10_15" / "bd-3u6o" / "verification_summary.md"
)

PROTOCOLS = [
    "remote_fencing",
    "cross_node_rollout",
    "epoch_barrier_participation",
    "distributed_saga_steps",
]
FAULT_CLASSES = ["DROP", "REORDER", "CORRUPT", "PARTITION"]
INVARIANTS = [
    "INV-VTF-DETERMINISTIC",
    "INV-VTF-CORRECT-OR-FAIL",
    "INV-VTF-NO-CUSTOM",
    "INV-VTF-SEED-STABLE",
]

RESULTS: list[dict[str, Any]] = []


def _check(check_id: str, name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "id": check_id,
        "check": name,
        "status": "PASS" if passed else "FAIL",
        "pass": bool(passed),
        "details": {"message": detail or ("found" if passed else "NOT FOUND")},
    }
    RESULTS.append(entry)
    return entry


def _safe_rel(path: Path) -> str:
    s_path, s_root = str(path), str(ROOT)
    if s_path.startswith(s_root):
        return str(path.relative_to(ROOT))
    return str(path)


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------


def check_doc_exists() -> None:
    """Testing doc must exist."""
    ok = DOC.is_file()
    _check(
        "CTF-001",
        "doc_exists",
        ok,
        f"found: {_safe_rel(DOC)}" if ok else f"MISSING: {_safe_rel(DOC)}",
    )


def check_report_exists() -> None:
    """Report artifact must exist."""
    ok = REPORT.is_file()
    _check(
        "CTF-002",
        "report_exists",
        ok,
        f"found: {_safe_rel(REPORT)}" if ok else f"MISSING: {_safe_rel(REPORT)}",
    )


def check_report_valid() -> None:
    """Report must be valid JSON with required fields."""
    if not REPORT.is_file():
        _check("CTF-003", "report_valid", False, "report file missing")
        return
    try:
        data = json.loads(REPORT.read_text())
        ok = (
            data.get("bead") == "bd-3u6o"
            and data.get("section") == "10.15"
            and data.get("adoption_status") == "documented"
            and isinstance(data.get("protocols"), list)
            and isinstance(data.get("fault_classes"), list)
            and isinstance(data.get("summary"), dict)
        )
        _check(
            "CTF-003",
            "report_valid",
            ok,
            "valid JSON with required fields" if ok else "missing required fields",
        )
    except (json.JSONDecodeError, KeyError) as exc:
        _check("CTF-003", "report_valid", False, f"parse error: {exc}")


def check_report_protocols() -> None:
    """Report must list all 4 protocols."""
    if not REPORT.is_file():
        _check("CTF-004", "report_protocols", False, "report file missing")
        return
    try:
        data = json.loads(REPORT.read_text())
        proto_names = [p.get("name") for p in data.get("protocols", [])]
        ok = all(p in proto_names for p in PROTOCOLS)
        _check(
            "CTF-004",
            "report_protocols",
            ok,
            f"{len(proto_names)}/4 protocols"
            if ok
            else f"missing protocols: {set(PROTOCOLS) - set(proto_names)}",
        )
    except (json.JSONDecodeError, KeyError) as exc:
        _check("CTF-004", "report_protocols", False, f"parse error: {exc}")


def check_report_fault_classes() -> None:
    """Report must list all 4 fault classes."""
    if not REPORT.is_file():
        _check("CTF-005", "report_fault_classes", False, "report file missing")
        return
    try:
        data = json.loads(REPORT.read_text())
        faults = data.get("fault_classes", [])
        ok = all(f in faults for f in FAULT_CLASSES)
        _check(
            "CTF-005",
            "report_fault_classes",
            ok,
            f"{len(faults)}/4 fault classes"
            if ok
            else f"missing: {set(FAULT_CLASSES) - set(faults)}",
        )
    except (json.JSONDecodeError, KeyError) as exc:
        _check("CTF-005", "report_fault_classes", False, f"parse error: {exc}")


def check_report_summary() -> None:
    """Report summary must show 20/20 passing."""
    if not REPORT.is_file():
        _check("CTF-006", "report_summary", False, "report file missing")
        return
    try:
        data = json.loads(REPORT.read_text())
        summary = data.get("summary", {})
        ok = (
            summary.get("total_tests") == 20
            and summary.get("passing") == 20
            and summary.get("failing") == 0
            and summary.get("seeds_used") == 5
        )
        _check(
            "CTF-006",
            "report_summary",
            ok,
            "20/20 tests, 5 seeds" if ok else f"unexpected summary: {summary}",
        )
    except (json.JSONDecodeError, KeyError) as exc:
        _check("CTF-006", "report_summary", False, f"parse error: {exc}")


def check_doc_protocols() -> None:
    """Testing doc must document all 4 protocols."""
    if not DOC.is_file():
        _check("CTF-007", "doc_protocols", False, "doc file missing")
        return
    text = DOC.read_text()
    protocol_terms = [
        "Remote Fencing",
        "Cross-Node Rollout",
        "Epoch Barrier",
        "Distributed Saga",
    ]
    ok = all(term in text for term in protocol_terms)
    _check(
        "CTF-007",
        "doc_protocols",
        ok,
        "all 4 protocols documented"
        if ok
        else "missing protocol documentation",
    )


def check_doc_fault_classes() -> None:
    """Testing doc must document all 4 fault classes."""
    if not DOC.is_file():
        _check("CTF-008", "doc_fault_classes", False, "doc file missing")
        return
    text = DOC.read_text()
    ok = all(f"**{fc}**" in text for fc in FAULT_CLASSES)
    _check(
        "CTF-008",
        "doc_fault_classes",
        ok,
        "all 4 fault classes documented"
        if ok
        else "missing fault class documentation",
    )


def check_doc_invariants() -> None:
    """Testing doc must document all 4 invariants."""
    if not DOC.is_file():
        _check("CTF-009", "doc_invariants", False, "doc file missing")
        return
    text = DOC.read_text()
    ok = all(inv in text for inv in INVARIANTS)
    _check(
        "CTF-009",
        "doc_invariants",
        ok,
        "all 4 invariants documented"
        if ok
        else f"missing invariants: {[i for i in INVARIANTS if i not in text]}",
    )


def check_doc_seed_model() -> None:
    """Testing doc must describe deterministic seed model."""
    if not DOC.is_file():
        _check("CTF-010", "doc_seed_model", False, "doc file missing")
        return
    text = DOC.read_text()
    has_seed = "seed" in text.lower()
    has_deterministic = "deterministic" in text.lower()
    has_prng = "PRNG" in text
    ok = has_seed and has_deterministic and has_prng
    _check(
        "CTF-010",
        "doc_seed_model",
        ok,
        "seed model with PRNG documented"
        if ok
        else "seed model documentation incomplete",
    )


def check_upstream_harness_exists() -> None:
    """Upstream harness source must exist."""
    ok = UPSTREAM_HARNESS.is_file()
    _check(
        "CTF-011",
        "upstream_harness_exists",
        ok,
        f"found: {_safe_rel(UPSTREAM_HARNESS)}"
        if ok
        else f"MISSING: {_safe_rel(UPSTREAM_HARNESS)}",
    )


def check_spec_exists() -> None:
    """Spec contract must exist."""
    ok = SPEC.is_file()
    _check(
        "CTF-012",
        "spec_exists",
        ok,
        f"found: {_safe_rel(SPEC)}" if ok else f"MISSING: {_safe_rel(SPEC)}",
    )


def check_spec_bead_id() -> None:
    """Spec must reference bd-3u6o."""
    if not SPEC.is_file():
        _check("CTF-013", "spec_bead_id", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "bd-3u6o" in text
    _check("CTF-013", "spec_bead_id", ok, "found" if ok else "NOT FOUND")


def check_spec_section() -> None:
    """Spec must reference section 10.15."""
    if not SPEC.is_file():
        _check("CTF-014", "spec_section", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "10.15" in text
    _check("CTF-014", "spec_section", ok, "found" if ok else "NOT FOUND")


def check_spec_invariants() -> None:
    """Spec must document all 4 invariants."""
    if not SPEC.is_file():
        _check("CTF-015", "spec_invariants", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = all(inv in text for inv in INVARIANTS)
    _check(
        "CTF-015",
        "spec_invariants",
        ok,
        "all 4 invariants in spec"
        if ok
        else f"missing: {[i for i in INVARIANTS if i not in text]}",
    )


def check_spec_acceptance_criteria() -> None:
    """Spec must have acceptance criteria."""
    if not SPEC.is_file():
        _check("CTF-016", "spec_acceptance_criteria", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "Acceptance Criteria" in text
    _check("CTF-016", "spec_acceptance_criteria", ok, "found" if ok else "NOT FOUND")


def check_unit_tests_exist() -> None:
    """Unit test file must exist."""
    ok = UNIT_TESTS.is_file()
    _check(
        "CTF-017",
        "unit_tests_exist",
        ok,
        f"found: {_safe_rel(UNIT_TESTS)}"
        if ok
        else f"MISSING: {_safe_rel(UNIT_TESTS)}",
    )


def check_verification_evidence() -> None:
    """Verification evidence artifact must exist and be valid."""
    if not EVIDENCE.is_file():
        _check(
            "CTF-018",
            "verification_evidence",
            False,
            f"MISSING: {_safe_rel(EVIDENCE)}",
        )
        return
    try:
        data = json.loads(EVIDENCE.read_text())
        ok = data.get("bead_id") == "bd-3u6o" and data.get("verdict") == "PASS"
        _check(
            "CTF-018",
            "verification_evidence",
            ok,
            f"valid: {_safe_rel(EVIDENCE)}"
            if ok
            else "evidence has incorrect bead_id or verdict",
        )
    except (json.JSONDecodeError, KeyError) as exc:
        _check("CTF-018", "verification_evidence", False, f"parse error: {exc}")


def check_verification_summary() -> None:
    """Verification summary artifact must exist."""
    ok = SUMMARY.is_file()
    _check(
        "CTF-019",
        "verification_summary",
        ok,
        f"found: {_safe_rel(SUMMARY)}" if ok else f"MISSING: {_safe_rel(SUMMARY)}",
    )


def check_doc_expected_behaviors() -> None:
    """Testing doc must describe expected behaviors for each protocol under faults."""
    if not DOC.is_file():
        _check("CTF-020", "doc_expected_behaviors", False, "doc file missing")
        return
    text = DOC.read_text().lower()
    has_retry = "retry" in text
    has_abort = "abort" in text
    has_compensate = "compensate" in text
    has_fail_closed = "fail" in text and "closed" in text
    ok = has_retry and has_abort and has_compensate and has_fail_closed
    _check(
        "CTF-020",
        "doc_expected_behaviors",
        ok,
        "retry, abort, compensate, fail-closed documented"
        if ok
        else "expected behavior documentation incomplete",
    )


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_doc_exists,
    check_report_exists,
    check_report_valid,
    check_report_protocols,
    check_report_fault_classes,
    check_report_summary,
    check_doc_protocols,
    check_doc_fault_classes,
    check_doc_invariants,
    check_doc_seed_model,
    check_upstream_harness_exists,
    check_spec_exists,
    check_spec_bead_id,
    check_spec_section,
    check_spec_invariants,
    check_spec_acceptance_criteria,
    check_unit_tests_exist,
    check_verification_evidence,
    check_verification_summary,
    check_doc_expected_behaviors,
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_all() -> dict[str, Any]:
    global RESULTS
    RESULTS = []
    for fn in ALL_CHECKS:
        fn()
    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    return {
        "bead_id": "bd-3u6o",
        "title": "canonical virtual transport fault harness for distributed control protocols",
        "section": "10.15",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


def self_test() -> bool:
    report = run_all()
    total, passed, failed = report["total"], report["passed"], report["failed"]
    print(f"self_test: {passed}/{total} checks pass, {failed} failing")
    if failed:
        for c in report["checks"]:
            if not c["pass"]:
                print(f"  FAIL: {c['id']} {c['check']} -- {c['details']['message']}")
    return failed == 0


def main() -> None:
    logger = configure_test_logging("check_control_transport_faults")
    parser = argparse.ArgumentParser(
        description="Verify bd-3u6o: canonical virtual transport fault harness"
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)
    report = run_all()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for c in report["checks"]:
            status = c["status"]
            print(f"[{status}] {c['id']} {c['check']}: {c['details']['message']}")
        print(
            f"\n{report['passed']}/{report['total']} checks pass"
            f" (verdict={report['verdict']})"
        )
    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
