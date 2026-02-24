#!/usr/bin/env python3
"""Verification script for bd-25oa: Enforce canonical DPOR-style schedule exploration
for epoch/lease/remote/evidence interactions.

Usage:
    python3 scripts/check_control_dpor_scope.py          # human output
    python3 scripts/check_control_dpor_scope.py --json    # JSON output
    python3 scripts/check_control_dpor_scope.py --self-test
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

# ---- File paths ----

SCOPE_DOC = ROOT / "docs" / "testing" / "control_dpor_scope.md"
SPEC_CONTRACT = ROOT / "docs" / "specs" / "section_10_15" / "bd-25oa_contract.md"
SUMMARY_REPORT = ROOT / "artifacts" / "10.15" / "control_dpor_exploration_summary.json"
UPSTREAM_DPOR = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "dpor_exploration.rs"
RESULTS_REPORT = ROOT / "artifacts" / "10.15" / "control_dpor_results.json"
EVIDENCE_JSON = ROOT / "artifacts" / "section_10_15" / "bd-25oa" / "verification_evidence.json"
EVIDENCE_SUMMARY = ROOT / "artifacts" / "section_10_15" / "bd-25oa" / "verification_summary.md"
TEST_FILE = ROOT / "tests" / "test_check_control_dpor_scope.py"
RUST_TEST_FILE = ROOT / "tests" / "lab" / "control_dpor_exploration.rs"

# ---- Required interaction classes ----

REQUIRED_CLASSES = [
    "epoch_transition_lease_renewal",
    "remote_computation_evidence_emission",
    "cancellation_saga_compensation",
    "epoch_barrier_fencing_token",
]

# ---- Required invariants in scope doc ----

REQUIRED_INVARIANTS = [
    "INV-DPOR-BOUNDED",
    "INV-DPOR-INVARIANT-CHECK",
    "INV-DPOR-COUNTEREXAMPLE",
    "INV-DPOR-CANONICAL",
]

# ---- Required upstream types in dpor_exploration.rs ----

REQUIRED_UPSTREAM_TYPES = [
    "DporExplorer",
    "ProtocolModel",
    "Operation",
    "SafetyProperty",
    "Counterexample",
    "CounterexampleStep",
    "ExplorationBudget",
    "ExplorationResult",
]

# ---- Required sections in scope doc ----

REQUIRED_DOC_SECTIONS = [
    "Protocol Interaction Classes",
    "DPOR Exploration Budget",
    "Invariant Assertions",
    "Counterexample Format",
    "Upstream Dependency",
]

# ---- Required report fields ----

REQUIRED_REPORT_KEYS = [
    "bead",
    "section",
    "adoption_status",
    "interaction_classes",
    "summary",
    "invariants_documented",
    "counterexample_format",
]

REQUIRED_SUMMARY_KEYS = [
    "total_interleavings",
    "classes_covered",
    "violations",
    "budget_respected",
]

REQUIRED_CLASS_KEYS = [
    "name",
    "interleavings_explored",
    "violations_found",
]

# ---- Budget keywords to find in scope doc ----

BUDGET_KEYWORDS = [
    "max_interleavings_per_class",
    "10000",
    "40000",
    "time_budget",
    "memory_budget",
]

# ---- DPR event codes (bd-25oa specific) ----

REQUIRED_DPR_EVENT_CODES = [
    "DPR-001",
    "DPR-002",
    "DPR-003",
    "DPR-004",
    "DPR-005",
]

# ---- Rust test file required content ----

RUST_TEST_MARKERS = [
    "InteractionClass",
    "ExplorationResult",
    "DporExplorer",
    "ExplorationBudget",
    "CounterexampleStep",
    "Counterexample",
    "epoch_transition_lease_renewal",
    "remote_computation_evidence_emission",
    "cancellation_saga_compensation",
    "epoch_barrier_fencing_token",
    "#[test]",
    "fn explore",
]

# ---- Counterexample format keywords ----

COUNTEREXAMPLE_KEYWORDS = [
    "model_name",
    "violated_property",
    "step_index",
    "operation_id",
    "state_summary",
    "Minimal",
]


def _safe_rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def _result(check_id: str, status: str, details: dict) -> dict:
    return {"id": check_id, "status": status, "details": details}


def _file_contains(path: Path, text: str) -> bool:
    if not path.exists():
        return False
    return text in path.read_text()


# ---- Check functions ----


def check_scope_doc_exists() -> dict:
    """CDP-001: Scope document exists."""
    exists = SCOPE_DOC.exists()
    return _result(
        "CDP-001",
        "PASS" if exists else "FAIL",
        {"file": _safe_rel(SCOPE_DOC), "found": exists},
    )


def check_report_exists_and_valid() -> dict:
    """CDP-002: Summary report exists and is valid JSON with required keys."""
    if not SUMMARY_REPORT.exists():
        return _result(
            "CDP-002",
            "FAIL",
            {"file": _safe_rel(SUMMARY_REPORT), "found": False},
        )
    try:
        data = json.loads(SUMMARY_REPORT.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        return _result(
            "CDP-002",
            "FAIL",
            {"file": _safe_rel(SUMMARY_REPORT), "error": str(exc)},
        )

    missing = [k for k in REQUIRED_REPORT_KEYS if k not in data]
    if missing:
        return _result(
            "CDP-002",
            "FAIL",
            {"file": _safe_rel(SUMMARY_REPORT), "missing_keys": missing},
        )

    # Validate summary sub-keys
    summary = data.get("summary", {})
    missing_summary = [k for k in REQUIRED_SUMMARY_KEYS if k not in summary]
    if missing_summary:
        return _result(
            "CDP-002",
            "FAIL",
            {"file": _safe_rel(SUMMARY_REPORT), "missing_summary_keys": missing_summary},
        )

    # Validate bead and section
    if data.get("bead") != "bd-25oa":
        return _result(
            "CDP-002",
            "FAIL",
            {"file": _safe_rel(SUMMARY_REPORT), "expected_bead": "bd-25oa", "actual": data.get("bead")},
        )
    if data.get("section") != "10.15":
        return _result(
            "CDP-002",
            "FAIL",
            {"file": _safe_rel(SUMMARY_REPORT), "expected_section": "10.15", "actual": data.get("section")},
        )

    return _result(
        "CDP-002",
        "PASS",
        {"file": _safe_rel(SUMMARY_REPORT), "keys_present": len(REQUIRED_REPORT_KEYS)},
    )


def check_interaction_classes_documented() -> list:
    """CDP-003: All 4 interaction classes documented in scope doc and report."""
    results = []

    # Check scope doc -- class names in the doc use various formats:
    # headings like "epoch_transition + lease_renewal", tables, or prose.
    # We check for the constituent parts split on '_' boundaries.
    _CLASS_DOC_MARKERS = {
        "epoch_transition_lease_renewal": "epoch_transition + lease_renewal",
        "remote_computation_evidence_emission": "remote_computation + evidence_emission",
        "cancellation_saga_compensation": "cancellation + saga_compensation",
        "epoch_barrier_fencing_token": "epoch_barrier + fencing_token",
    }
    for cls in REQUIRED_CLASSES:
        marker = _CLASS_DOC_MARKERS.get(cls, cls)
        found_in_doc = _file_contains(SCOPE_DOC, marker) or _file_contains(SCOPE_DOC, cls)
        results.append(
            _result(
                "CDP-003",
                "PASS" if found_in_doc else "FAIL",
                {"class": cls, "location": "scope_doc", "found": found_in_doc},
            )
        )

    # Check report
    if SUMMARY_REPORT.exists():
        try:
            data = json.loads(SUMMARY_REPORT.read_text())
            report_classes = [c.get("name") for c in data.get("interaction_classes", [])]
            for cls in REQUIRED_CLASSES:
                found = cls in report_classes
                results.append(
                    _result(
                        "CDP-003",
                        "PASS" if found else "FAIL",
                        {"class": cls, "location": "report", "found": found},
                    )
                )
        except (json.JSONDecodeError, OSError):
            for cls in REQUIRED_CLASSES:
                results.append(
                    _result("CDP-003", "FAIL", {"class": cls, "location": "report", "error": "parse_failed"})
                )
    else:
        for cls in REQUIRED_CLASSES:
            results.append(
                _result("CDP-003", "FAIL", {"class": cls, "location": "report", "found": False})
            )

    # Check class entries have required keys
    if SUMMARY_REPORT.exists():
        try:
            data = json.loads(SUMMARY_REPORT.read_text())
            for entry in data.get("interaction_classes", []):
                missing_keys = [k for k in REQUIRED_CLASS_KEYS if k not in entry]
                name = entry.get("name", "unknown")
                results.append(
                    _result(
                        "CDP-003",
                        "PASS" if not missing_keys else "FAIL",
                        {"class": name, "location": "report_entry", "missing_keys": missing_keys},
                    )
                )
                # Verify zero violations
                vf = entry.get("violations_found", -1)
                results.append(
                    _result(
                        "CDP-003",
                        "PASS" if vf == 0 else "FAIL",
                        {"class": name, "violations_found": vf, "expected": 0},
                    )
                )
        except (json.JSONDecodeError, OSError):
            pass

    return results


def check_upstream_explorer() -> list:
    """CDP-004: Upstream DPOR explorer exists and contains required types."""
    results = []

    exists = UPSTREAM_DPOR.exists()
    results.append(
        _result(
            "CDP-004",
            "PASS" if exists else "FAIL",
            {"file": _safe_rel(UPSTREAM_DPOR), "found": exists},
        )
    )

    if exists:
        content = UPSTREAM_DPOR.read_text()
        for typ in REQUIRED_UPSTREAM_TYPES:
            found = typ in content
            results.append(
                _result(
                    "CDP-004",
                    "PASS" if found else "FAIL",
                    {"upstream_type": typ, "found": found},
                )
            )
    else:
        for typ in REQUIRED_UPSTREAM_TYPES:
            results.append(
                _result("CDP-004", "FAIL", {"upstream_type": typ, "found": False})
            )

    return results


def check_budget_defined() -> list:
    """CDP-005: Budget constraints are documented in scope doc."""
    results = []
    for kw in BUDGET_KEYWORDS:
        found = _file_contains(SCOPE_DOC, kw)
        results.append(
            _result(
                "CDP-005",
                "PASS" if found else "FAIL",
                {"keyword": kw, "found": found},
            )
        )

    # Check report budget_respected
    if SUMMARY_REPORT.exists():
        try:
            data = json.loads(SUMMARY_REPORT.read_text())
            br = data.get("summary", {}).get("budget_respected", False)
            results.append(
                _result(
                    "CDP-005",
                    "PASS" if br else "FAIL",
                    {"report_budget_respected": br},
                )
            )
        except (json.JSONDecodeError, OSError):
            results.append(_result("CDP-005", "FAIL", {"report_budget_respected": False}))
    else:
        results.append(_result("CDP-005", "FAIL", {"report_budget_respected": False}))

    return results


def check_invariants_documented() -> list:
    """CDP-006: Invariant assertions are documented in scope doc and report."""
    results = []

    for inv in REQUIRED_INVARIANTS:
        found_doc = _file_contains(SCOPE_DOC, inv)
        results.append(
            _result(
                "CDP-006",
                "PASS" if found_doc else "FAIL",
                {"invariant": inv, "location": "scope_doc", "found": found_doc},
            )
        )

        found_spec = _file_contains(SPEC_CONTRACT, inv)
        results.append(
            _result(
                "CDP-006",
                "PASS" if found_spec else "FAIL",
                {"invariant": inv, "location": "spec_contract", "found": found_spec},
            )
        )

    # Check report invariants_documented list
    if SUMMARY_REPORT.exists():
        try:
            data = json.loads(SUMMARY_REPORT.read_text())
            report_invs = data.get("invariants_documented", [])
            for inv in REQUIRED_INVARIANTS:
                found = inv in report_invs
                results.append(
                    _result(
                        "CDP-006",
                        "PASS" if found else "FAIL",
                        {"invariant": inv, "location": "report", "found": found},
                    )
                )
        except (json.JSONDecodeError, OSError):
            for inv in REQUIRED_INVARIANTS:
                results.append(_result("CDP-006", "FAIL", {"invariant": inv, "location": "report", "found": False}))
    else:
        for inv in REQUIRED_INVARIANTS:
            results.append(_result("CDP-006", "FAIL", {"invariant": inv, "location": "report", "found": False}))

    return results


def check_counterexample_format() -> list:
    """CDP-007: Counterexample format is documented."""
    results = []

    for kw in COUNTEREXAMPLE_KEYWORDS:
        found = _file_contains(SCOPE_DOC, kw)
        results.append(
            _result(
                "CDP-007",
                "PASS" if found else "FAIL",
                {"keyword": kw, "found": found},
            )
        )

    # Check report counterexample_format
    if SUMMARY_REPORT.exists():
        try:
            data = json.loads(SUMMARY_REPORT.read_text())
            ce_format = data.get("counterexample_format", {})
            has_fields = "fields" in ce_format and "step_fields" in ce_format
            results.append(
                _result(
                    "CDP-007",
                    "PASS" if has_fields else "FAIL",
                    {"report_counterexample_format": has_fields},
                )
            )
        except (json.JSONDecodeError, OSError):
            results.append(_result("CDP-007", "FAIL", {"report_counterexample_format": False}))
    else:
        results.append(_result("CDP-007", "FAIL", {"report_counterexample_format": False}))

    return results


def check_doc_sections() -> list:
    """CDP-008a: Required sections present in scope document."""
    results = []
    for section in REQUIRED_DOC_SECTIONS:
        found = _file_contains(SCOPE_DOC, section)
        results.append(
            _result(
                "CDP-008",
                "PASS" if found else "FAIL",
                {"section": section, "location": "scope_doc", "found": found},
            )
        )
    return results


def check_spec_exists() -> dict:
    """CDP-008b: Spec contract exists."""
    exists = SPEC_CONTRACT.exists()
    return _result(
        "CDP-008",
        "PASS" if exists else "FAIL",
        {"file": _safe_rel(SPEC_CONTRACT), "found": exists},
    )


def check_test_file_exists() -> dict:
    """CDP-008c: Test file exists."""
    exists = TEST_FILE.exists()
    return _result(
        "CDP-008",
        "PASS" if exists else "FAIL",
        {"file": _safe_rel(TEST_FILE), "found": exists},
    )


def check_report_summary_totals() -> list:
    """CDP-008d: Report summary totals are consistent."""
    results = []
    if not SUMMARY_REPORT.exists():
        results.append(_result("CDP-008", "FAIL", {"check": "summary_totals", "found": False}))
        return results

    try:
        data = json.loads(SUMMARY_REPORT.read_text())
    except (json.JSONDecodeError, OSError):
        results.append(_result("CDP-008", "FAIL", {"check": "summary_totals", "parse_error": True}))
        return results

    summary = data.get("summary", {})
    classes = data.get("interaction_classes", [])

    # classes_covered should match length
    cc = summary.get("classes_covered", 0)
    actual = len(classes)
    results.append(
        _result(
            "CDP-008",
            "PASS" if cc == actual else "FAIL",
            {"check": "classes_covered", "expected": actual, "actual": cc},
        )
    )

    # total_interleavings should equal sum of per-class
    total_claimed = summary.get("total_interleavings", 0)
    total_computed = sum(c.get("interleavings_explored", 0) for c in classes)
    results.append(
        _result(
            "CDP-008",
            "PASS" if total_claimed == total_computed else "FAIL",
            {"check": "total_interleavings", "claimed": total_claimed, "computed": total_computed},
        )
    )

    # violations should be 0
    viol = summary.get("violations", -1)
    results.append(
        _result(
            "CDP-008",
            "PASS" if viol == 0 else "FAIL",
            {"check": "violations", "expected": 0, "actual": viol},
        )
    )

    # adoption_status should be "documented"
    status = data.get("adoption_status", "")
    results.append(
        _result(
            "CDP-008",
            "PASS" if status == "documented" else "FAIL",
            {"check": "adoption_status", "expected": "documented", "actual": status},
        )
    )

    return results


def check_rust_test_file() -> list:
    """DPR-001: Rust DPOR exploration test file exists and contains required markers."""
    results = []

    exists = RUST_TEST_FILE.exists()
    results.append(
        _result(
            "DPR-001",
            "PASS" if exists else "FAIL",
            {"file": _safe_rel(RUST_TEST_FILE), "found": exists},
        )
    )

    if exists:
        content = RUST_TEST_FILE.read_text()
        for marker in RUST_TEST_MARKERS:
            found = marker in content
            results.append(
                _result(
                    "DPR-001",
                    "PASS" if found else "FAIL",
                    {"rust_marker": marker, "found": found},
                )
            )

        # Count #[test] annotations -- require at least 12
        test_count = content.count("#[test]")
        results.append(
            _result(
                "DPR-001",
                "PASS" if test_count >= 12 else "FAIL",
                {"rust_test_count": test_count, "required": 12},
            )
        )

        # Verify all 4 interaction classes are tested
        for cls in REQUIRED_CLASSES:
            found = cls in content
            results.append(
                _result(
                    "DPR-001",
                    "PASS" if found else "FAIL",
                    {"rust_class": cls, "found": found},
                )
            )
    else:
        for marker in RUST_TEST_MARKERS:
            results.append(
                _result("DPR-001", "FAIL", {"rust_marker": marker, "found": False})
            )
        results.append(
            _result("DPR-001", "FAIL", {"rust_test_count": 0, "required": 12})
        )
        for cls in REQUIRED_CLASSES:
            results.append(
                _result("DPR-001", "FAIL", {"rust_class": cls, "found": False})
            )

    return results


def check_dpr_event_codes() -> list:
    """DPR-002: DPR event codes are documented in scope doc and spec contract."""
    results = []

    for code in REQUIRED_DPR_EVENT_CODES:
        found_doc = _file_contains(SCOPE_DOC, code)
        results.append(
            _result(
                "DPR-002",
                "PASS" if found_doc else "FAIL",
                {"event_code": code, "location": "scope_doc", "found": found_doc},
            )
        )

        found_spec = _file_contains(SPEC_CONTRACT, code)
        results.append(
            _result(
                "DPR-002",
                "PASS" if found_spec else "FAIL",
                {"event_code": code, "location": "spec_contract", "found": found_spec},
            )
        )

    return results


def check_results_report() -> list:
    """DPR-003: DPOR results report exists and is valid."""
    results = []

    exists = RESULTS_REPORT.exists()
    results.append(
        _result(
            "DPR-003",
            "PASS" if exists else "FAIL",
            {"file": _safe_rel(RESULTS_REPORT), "found": exists},
        )
    )

    if not exists:
        return results

    try:
        data = json.loads(RESULTS_REPORT.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        results.append(
            _result("DPR-003", "FAIL", {"file": _safe_rel(RESULTS_REPORT), "error": str(exc)})
        )
        return results

    # Check bead_id
    bead_ok = data.get("bead_id") == "bd-25oa"
    results.append(
        _result(
            "DPR-003",
            "PASS" if bead_ok else "FAIL",
            {"check": "bead_id", "expected": "bd-25oa", "actual": data.get("bead_id")},
        )
    )

    # Check verdict
    verdict_ok = data.get("verdict") == "PASS"
    results.append(
        _result(
            "DPR-003",
            "PASS" if verdict_ok else "FAIL",
            {"check": "verdict", "expected": "PASS", "actual": data.get("verdict")},
        )
    )

    # Check 4 interaction classes
    ic = data.get("interaction_classes", [])
    ic_count_ok = len(ic) == 4
    results.append(
        _result(
            "DPR-003",
            "PASS" if ic_count_ok else "FAIL",
            {"check": "interaction_classes_count", "expected": 4, "actual": len(ic)},
        )
    )

    # Check all classes pass
    for entry in ic:
        name = entry.get("name", "unknown")
        passed = entry.get("passed", False) is True and entry.get("violations_found", -1) == 0
        results.append(
            _result(
                "DPR-003",
                "PASS" if passed else "FAIL",
                {"check": "class_passed", "class": name, "passed": passed},
            )
        )

    # Check DPR event codes in results
    ev_codes = data.get("event_codes", [])
    for code in REQUIRED_DPR_EVENT_CODES:
        found = code in ev_codes
        results.append(
            _result(
                "DPR-003",
                "PASS" if found else "FAIL",
                {"check": "event_code_in_results", "code": code, "found": found},
            )
        )

    return results


def check_evidence_artifacts() -> list:
    """DPR-004: Verification evidence and summary exist."""
    results = []

    ev_exists = EVIDENCE_JSON.exists()
    results.append(
        _result(
            "DPR-004",
            "PASS" if ev_exists else "FAIL",
            {"file": _safe_rel(EVIDENCE_JSON), "found": ev_exists},
        )
    )

    summary_exists = EVIDENCE_SUMMARY.exists()
    results.append(
        _result(
            "DPR-004",
            "PASS" if summary_exists else "FAIL",
            {"file": _safe_rel(EVIDENCE_SUMMARY), "found": summary_exists},
        )
    )

    return results


# ---- Main runner ----


def run_checks() -> dict:
    checks = []
    checks.append(check_scope_doc_exists())
    checks.append(check_report_exists_and_valid())
    checks.extend(check_interaction_classes_documented())
    checks.extend(check_upstream_explorer())
    checks.extend(check_budget_defined())
    checks.extend(check_invariants_documented())
    checks.extend(check_counterexample_format())
    checks.extend(check_doc_sections())
    checks.append(check_spec_exists())
    checks.append(check_test_file_exists())
    checks.extend(check_report_summary_totals())
    checks.extend(check_rust_test_file())
    checks.extend(check_dpr_event_codes())
    checks.extend(check_results_report())
    checks.extend(check_evidence_artifacts())

    passing = sum(1 for c in checks if c["status"] == "PASS")
    failing = sum(1 for c in checks if c["status"] == "FAIL")
    verdict = "PASS" if failing == 0 else "FAIL"

    return {
        "bead_id": "bd-25oa",
        "title": "Enforce canonical DPOR-style schedule exploration for control-plane interactions",
        "section": "10.15",
        "overall_pass": failing == 0,
        "verdict": verdict,
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": passing + failing,
        },
        "checks": checks,
    }


def self_test() -> tuple:
    result = run_checks()
    if not result["overall_pass"]:
        failures = [c for c in result["checks"] if c["status"] == "FAIL"]
        detail = "; ".join(
            f"{c['id']}: {json.dumps(c['details'])}" for c in failures[:5]
        )
        return False, f"self_test failed: {detail}"
    return True, "self_test passed"


def main():
    logger = configure_test_logging("check_control_dpor_scope")
    if "--self-test" in sys.argv:
        ok, msg = self_test()
        print(msg)
        sys.exit(0 if ok else 1)

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["overall_pass"] else 1)

    for c in result["checks"]:
        status = c["status"]
        print(f"  [{status}] {c['id']}: {json.dumps(c['details'])}")

    passing = result["summary"]["passing"]
    failing = result["summary"]["failing"]
    total = result["summary"]["total"]
    print(
        f"\nbd-25oa verification: {result['verdict']} ({passing}/{total} checks pass)"
    )
    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
