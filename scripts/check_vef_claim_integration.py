#!/usr/bin/env python3
"""Verification script for bd-3go4: VEF coverage and proof-validity metrics integration.

Checks that the VEF claim coverage snapshot, verification evidence, spec document,
and conformance tests are present, complete, and internally consistent.

Usage:
    python3 scripts/check_vef_claim_integration.py            # human-readable
    python3 scripts/check_vef_claim_integration.py --json      # machine-readable
    python3 scripts/check_vef_claim_integration.py --self-test  # smoke-test
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "docs" / "specs" / "vef_claim_integration.md"
CONFORMANCE = ROOT / "tests" / "conformance" / "vef_claim_gate.rs"
SNAPSHOT = ROOT / "artifacts" / "10.18" / "vef_claim_coverage_snapshot.json"
EVIDENCE = ROOT / "artifacts" / "section_10_18" / "bd-3go4" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_18" / "bd-3go4" / "verification_summary.md"
IMPL = ROOT / "crates" / "franken-node" / "src" / "connector" / "vef_claim_integration.rs"

DEFAULT_MIN_COVERAGE_PCT = 80.0

EVENT_CODES = ["VEF-CLAIM-001", "VEF-CLAIM-002", "VEF-CLAIM-003", "VEF-SCORE-001"]
INVARIANTS = [
    "INV-VEF-CLAIM-GATE",
    "INV-VEF-CLAIM-DETERMINISTIC",
    "INV-VEF-SCORE-TRACEABLE",
    "INV-VEF-SCORE-REPRODUCIBLE",
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


def _safe_rel(path: Path) -> str:
    s_path, s_root = str(path), str(ROOT)
    if s_path.startswith(s_root):
        return str(path.relative_to(ROOT))
    return str(path)


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------


def check_spec_exists() -> None:
    """Spec document must exist."""
    ok = SPEC.is_file()
    _check(
        "spec_exists",
        ok,
        f"found: {_safe_rel(SPEC)}" if ok else f"MISSING: {_safe_rel(SPEC)}",
    )


def check_spec_bead_id() -> None:
    """Spec must reference bd-3go4."""
    if not SPEC.is_file():
        _check("spec_bead_id", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "bd-3go4" in text
    _check("spec_bead_id", ok, "found" if ok else "NOT FOUND")


def check_spec_section() -> None:
    """Spec must reference section 10.18."""
    if not SPEC.is_file():
        _check("spec_section_10_18", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "10.18" in text
    _check("spec_section_10_18", ok, "found" if ok else "NOT FOUND")


def check_spec_event_codes() -> None:
    """Spec must contain all event codes."""
    if not SPEC.is_file():
        for code in EVENT_CODES:
            _check(f"spec_event_code_{code}", False, "spec file missing")
        return
    text = SPEC.read_text()
    for code in EVENT_CODES:
        ok = code in text
        _check(f"spec_event_code_{code}", ok, "found" if ok else "NOT FOUND")


def check_spec_invariants() -> None:
    """Spec must contain all invariants."""
    if not SPEC.is_file():
        for inv in INVARIANTS:
            _check(f"spec_invariant_{inv}", False, "spec file missing")
        return
    text = SPEC.read_text()
    for inv in INVARIANTS:
        ok = inv in text
        _check(f"spec_invariant_{inv}", ok, "found" if ok else "NOT FOUND")


def check_spec_acceptance_criteria() -> None:
    """Spec must have acceptance criteria section."""
    if not SPEC.is_file():
        _check("spec_acceptance_criteria", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "Acceptance Criteria" in text
    _check("spec_acceptance_criteria", ok, "found" if ok else "NOT FOUND")


def check_spec_test_scenarios() -> None:
    """Spec must have test scenarios section."""
    if not SPEC.is_file():
        _check("spec_test_scenarios", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "Scenario" in text
    _check("spec_test_scenarios", ok, "found" if ok else "NOT FOUND")


def check_conformance_exists() -> None:
    """Conformance test file must exist."""
    ok = CONFORMANCE.is_file()
    _check(
        "conformance_exists",
        ok,
        f"found: {_safe_rel(CONFORMANCE)}" if ok else f"MISSING: {_safe_rel(CONFORMANCE)}",
    )


def check_conformance_tests() -> None:
    """Conformance test file must contain required test functions."""
    if not CONFORMANCE.is_file():
        _check("conformance_tests", False, "conformance file missing")
        return
    text = CONFORMANCE.read_text()
    required_tests = [
        "test_claim_passes_with_full_coverage",
        "test_claim_blocked_below_threshold",
        "test_coverage_gap_detection",
        "test_evidence_link_validity",
        "test_threshold_boundary",
    ]
    missing = [t for t in required_tests if t not in text]
    ok = len(missing) == 0
    _check(
        "conformance_tests",
        ok,
        f"all {len(required_tests)} tests present"
        if ok
        else f"missing tests: {', '.join(missing)}",
    )


def check_snapshot_exists() -> None:
    """Coverage snapshot artifact must exist."""
    ok = SNAPSHOT.is_file()
    _check(
        "snapshot_exists",
        ok,
        f"found: {_safe_rel(SNAPSHOT)}" if ok else f"MISSING: {_safe_rel(SNAPSHOT)}",
    )


def check_snapshot_valid_json() -> None:
    """Coverage snapshot must be valid JSON."""
    if not SNAPSHOT.is_file():
        _check("snapshot_valid_json", False, "snapshot file missing")
        return
    try:
        json.loads(SNAPSHOT.read_text())
        _check("snapshot_valid_json", True, "valid JSON")
    except json.JSONDecodeError as exc:
        _check("snapshot_valid_json", False, f"parse error: {exc}")


def check_snapshot_bead_id() -> None:
    """Snapshot must reference bd-3go4."""
    if not SNAPSHOT.is_file():
        _check("snapshot_bead_id", False, "snapshot file missing")
        return
    try:
        data = json.loads(SNAPSHOT.read_text())
        ok = data.get("bead_id") == "bd-3go4"
        _check("snapshot_bead_id", ok, "found" if ok else "NOT FOUND or incorrect")
    except (json.JSONDecodeError, KeyError) as exc:
        _check("snapshot_bead_id", False, f"error: {exc}")


def check_snapshot_coverage() -> None:
    """Snapshot coverage_percentage must be >= configured threshold."""
    if not SNAPSHOT.is_file():
        _check("snapshot_coverage", False, "snapshot file missing")
        return
    try:
        data = json.loads(SNAPSHOT.read_text())
        cov = data.get("coverage", {})
        pct = cov.get("coverage_percentage", 0.0)
        ok = pct >= DEFAULT_MIN_COVERAGE_PCT
        _check(
            "snapshot_coverage",
            ok,
            f"coverage {pct}% >= {DEFAULT_MIN_COVERAGE_PCT}%"
            if ok
            else f"coverage {pct}% below {DEFAULT_MIN_COVERAGE_PCT}%",
        )
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        _check("snapshot_coverage", False, f"error: {exc}")


def check_snapshot_claim_gates() -> None:
    """All claim gate results in the snapshot must be PASS."""
    if not SNAPSHOT.is_file():
        _check("snapshot_claim_gates", False, "snapshot file missing")
        return
    try:
        data = json.loads(SNAPSHOT.read_text())
        results = data.get("claim_gate_results", [])
        if not results:
            _check("snapshot_claim_gates", False, "no claim gate results found")
            return
        failed = [r for r in results if r.get("verdict") != "PASS"]
        ok = len(failed) == 0
        _check(
            "snapshot_claim_gates",
            ok,
            f"all {len(results)} claims pass"
            if ok
            else f"{len(failed)} claims failed: {[r.get('claim_id') for r in failed]}",
        )
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        _check("snapshot_claim_gates", False, f"error: {exc}")


def check_snapshot_verdict() -> None:
    """Snapshot verdict must be PASS."""
    if not SNAPSHOT.is_file():
        _check("snapshot_verdict", False, "snapshot file missing")
        return
    try:
        data = json.loads(SNAPSHOT.read_text())
        ok = data.get("verdict") == "PASS"
        _check(
            "snapshot_verdict",
            ok,
            "PASS" if ok else f"unexpected verdict: {data.get('verdict')}",
        )
    except (json.JSONDecodeError, KeyError) as exc:
        _check("snapshot_verdict", False, f"error: {exc}")


def check_evidence_exists() -> None:
    """Verification evidence artifact must exist."""
    ok = EVIDENCE.is_file()
    _check(
        "evidence_exists",
        ok,
        f"found: {_safe_rel(EVIDENCE)}" if ok else f"MISSING: {_safe_rel(EVIDENCE)}",
    )


def check_evidence_valid() -> None:
    """Verification evidence must be valid and reference bd-3go4."""
    if not EVIDENCE.is_file():
        _check("evidence_valid", False, "evidence file missing")
        return
    try:
        data = json.loads(EVIDENCE.read_text())
        ok = data.get("bead_id") == "bd-3go4" and data.get("verdict") == "PASS"
        _check(
            "evidence_valid",
            ok,
            "valid: bead_id and verdict correct"
            if ok
            else "evidence has incorrect bead_id or verdict",
        )
    except (json.JSONDecodeError, KeyError) as exc:
        _check("evidence_valid", False, f"parse error: {exc}")


def check_summary_exists() -> None:
    """Verification summary must exist."""
    ok = SUMMARY.is_file()
    _check(
        "summary_exists",
        ok,
        f"found: {_safe_rel(SUMMARY)}" if ok else f"MISSING: {_safe_rel(SUMMARY)}",
    )


def check_impl_exists() -> None:
    """Rust implementation file must exist."""
    ok = IMPL.is_file()
    _check(
        "impl_exists",
        ok,
        f"found: {_safe_rel(IMPL)}" if ok else f"MISSING: {_safe_rel(IMPL)}",
    )


def check_impl_event_codes() -> None:
    """Implementation must reference all event codes."""
    if not IMPL.is_file():
        for code in EVENT_CODES:
            _check(f"impl_event_code_{code}", False, "impl file missing")
        return
    text = IMPL.read_text()
    for code in EVENT_CODES:
        ok = code in text
        _check(f"impl_event_code_{code}", ok, "found" if ok else "NOT FOUND")


def check_impl_invariants() -> None:
    """Implementation must reference all invariants."""
    if not IMPL.is_file():
        for inv in INVARIANTS:
            _check(f"impl_invariant_{inv}", False, "impl file missing")
        return
    text = IMPL.read_text()
    for inv in INVARIANTS:
        ok = inv in text
        _check(f"impl_invariant_{inv}", ok, "found" if ok else "NOT FOUND")


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_spec_bead_id,
    check_spec_section,
    check_spec_event_codes,
    check_spec_invariants,
    check_spec_acceptance_criteria,
    check_spec_test_scenarios,
    check_conformance_exists,
    check_conformance_tests,
    check_snapshot_exists,
    check_snapshot_valid_json,
    check_snapshot_bead_id,
    check_snapshot_coverage,
    check_snapshot_claim_gates,
    check_snapshot_verdict,
    check_evidence_exists,
    check_evidence_valid,
    check_summary_exists,
    check_impl_exists,
    check_impl_event_codes,
    check_impl_invariants,
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
        "bead_id": "bd-3go4",
        "title": "VEF coverage and proof-validity metrics integration",
        "section": "10.18",
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
                print(f"  FAIL: {c['check']} -- {c['detail']}")
    return failed == 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify bd-3go4: VEF coverage and proof-validity metrics integration"
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
            status = "PASS" if c["pass"] else "FAIL"
            print(f"[{status}] {c['check']}: {c['detail']}")
        print(
            f"\n{report['passed']}/{report['total']} checks pass"
            f" (verdict={report['verdict']})"
        )
    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
