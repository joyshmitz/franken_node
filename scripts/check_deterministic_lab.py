#!/usr/bin/env python3
"""bd-2ko: Deterministic lab runtime verification gate (Section 10.11).

Validates that the deterministic lab testing infrastructure exists and is
correctly implemented: lab_runtime.rs (FN-LB event codes), virtual_transport.rs
(VT event codes), scenario_builder.rs (SB event codes), the bd-2ko spec
contract, and the verification evidence artifact.

Usage:
    python scripts/check_deterministic_lab.py            # human-readable
    python scripts/check_deterministic_lab.py --json     # machine-readable JSON
    python scripts/check_deterministic_lab.py --self-test # self-test mode
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


def _find_project_root() -> Path:
    """Walk upward from the script location to find the nearest directory
    containing Cargo.toml."""
    current = Path(__file__).resolve().parent
    while True:
        if (current / "Cargo.toml").is_file():
            return current
        parent = current.parent
        if parent == current:
            # Reached filesystem root without finding Cargo.toml; fall back
            # to the conventional two-levels-up location.
            return Path(__file__).resolve().parent.parent
        current = parent


ROOT = _find_project_root()

# ---------------------------------------------------------------------------
# Paths under verification
# ---------------------------------------------------------------------------

LAB_RUNTIME_RS = (
    ROOT / "crates" / "franken-node" / "src" / "testing" / "lab_runtime.rs"
)
VIRTUAL_TRANSPORT_RS = (
    ROOT / "crates" / "franken-node" / "src" / "testing" / "virtual_transport.rs"
)
SCENARIO_BUILDER_RS = (
    ROOT / "crates" / "franken-node" / "src" / "testing" / "scenario_builder.rs"
)
SPEC_CONTRACT = ROOT / "docs" / "specs" / "section_10_11" / "bd-2ko_contract.md"
EVIDENCE_JSON = (
    ROOT / "artifacts" / "section_10_11" / "bd-2ko" / "verification_evidence.json"
)

# ---------------------------------------------------------------------------
# Required event code sets
# ---------------------------------------------------------------------------

LAB_EVENT_CODES = [
    "FN-LB-001",
    "FN-LB-002",
    "FN-LB-003",
    "FN-LB-004",
    "FN-LB-005",
    "FN-LB-006",
    "FN-LB-007",
    "FN-LB-008",
    "FN-LB-009",
    "FN-LB-010",
]

VT_EVENT_CODES = [
    "VT-001",
    "VT-002",
    "VT-003",
    "VT-004",
    "VT-005",
    "VT-006",
    "VT-007",
    "VT-008",
]

SB_EVENT_CODES = [
    "SB-001",
    "SB-002",
    "SB-003",
    "SB-004",
]

# Required top-level fields in the verification evidence JSON.
EVIDENCE_REQUIRED_FIELDS = {
    "bead_id",
    "section",
    "scenarios_executed",
    "interleavings_explored",
    "determinism_verified",
    "bugs_found",
}

# ---------------------------------------------------------------------------
# Check accumulator
# ---------------------------------------------------------------------------

CHECKS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> None:
    """Record a single check result."""
    CHECKS.append(
        {
            "check": name,
            "pass": bool(passed),
            "detail": detail or ("found" if passed else "NOT FOUND"),
        }
    )


def _safe_rel(path: Path) -> str:
    """Return a project-relative path string when possible."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _read(path: Path) -> str:
    """Read a file's text content or return empty string if missing."""
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def _load_json(path: Path) -> dict[str, Any] | None:
    """Load and parse a JSON file, returning None on any error."""
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if isinstance(data, dict):
        return data
    return None


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------


def check_lab_runtime_exists() -> None:
    """lab_runtime.rs must exist."""
    _check("lab_runtime.rs exists", LAB_RUNTIME_RS.is_file(), _safe_rel(LAB_RUNTIME_RS))


def check_lab_runtime_event_codes() -> None:
    """lab_runtime.rs must contain all FN-LB-001 through FN-LB-010 event codes."""
    src = _read(LAB_RUNTIME_RS)
    missing: list[str] = []
    for code in LAB_EVENT_CODES:
        if code not in src:
            missing.append(code)
    passed = len(missing) == 0
    detail = "all 10 event codes present" if passed else f"missing: {', '.join(missing)}"
    _check("lab_runtime.rs event codes FN-LB-001..010", passed, detail)


def check_virtual_transport_exists() -> None:
    """virtual_transport.rs must exist."""
    _check(
        "virtual_transport.rs exists",
        VIRTUAL_TRANSPORT_RS.is_file(),
        _safe_rel(VIRTUAL_TRANSPORT_RS),
    )


def check_virtual_transport_event_codes() -> None:
    """virtual_transport.rs must contain VT event codes."""
    src = _read(VIRTUAL_TRANSPORT_RS)
    missing: list[str] = []
    for code in VT_EVENT_CODES:
        if code not in src:
            missing.append(code)
    passed = len(missing) == 0
    detail = (
        f"all {len(VT_EVENT_CODES)} VT event codes present"
        if passed
        else f"missing: {', '.join(missing)}"
    )
    _check("virtual_transport.rs VT event codes", passed, detail)


def check_scenario_builder_exists() -> None:
    """scenario_builder.rs must exist."""
    _check(
        "scenario_builder.rs exists",
        SCENARIO_BUILDER_RS.is_file(),
        _safe_rel(SCENARIO_BUILDER_RS),
    )


def check_scenario_builder_event_codes() -> None:
    """scenario_builder.rs must contain SB event codes."""
    src = _read(SCENARIO_BUILDER_RS)
    missing: list[str] = []
    for code in SB_EVENT_CODES:
        if code not in src:
            missing.append(code)
    passed = len(missing) == 0
    detail = (
        f"all {len(SB_EVENT_CODES)} SB event codes present"
        if passed
        else f"missing: {', '.join(missing)}"
    )
    _check("scenario_builder.rs SB event codes", passed, detail)


def check_spec_contract_exists() -> None:
    """bd-2ko_contract.md must exist."""
    _check("spec contract exists", SPEC_CONTRACT.is_file(), _safe_rel(SPEC_CONTRACT))


def check_evidence_exists() -> None:
    """verification_evidence.json must exist."""
    _check("evidence JSON exists", EVIDENCE_JSON.is_file(), _safe_rel(EVIDENCE_JSON))


def check_evidence_valid_json() -> None:
    """verification_evidence.json must be valid JSON."""
    data = _load_json(EVIDENCE_JSON)
    _check(
        "evidence JSON is valid",
        data is not None,
        "valid JSON object" if data is not None else "invalid or missing JSON",
    )


def check_evidence_required_fields() -> None:
    """verification_evidence.json must contain all required top-level fields."""
    data = _load_json(EVIDENCE_JSON)
    if data is None:
        _check("evidence required fields", False, "cannot parse evidence JSON")
        return
    missing = sorted(EVIDENCE_REQUIRED_FIELDS - set(data.keys()))
    passed = len(missing) == 0
    detail = "all required fields present" if passed else f"missing: {', '.join(missing)}"
    _check("evidence required fields", passed, detail)


def check_evidence_determinism_verified() -> None:
    """verification_evidence.json determinism_verified must be true."""
    data = _load_json(EVIDENCE_JSON)
    if data is None:
        _check("determinism_verified is true", False, "cannot parse evidence JSON")
        return
    value = data.get("determinism_verified")
    passed = value is True
    _check("determinism_verified is true", passed, f"determinism_verified={value}")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_checks() -> dict[str, Any]:
    """Execute all checks and return a structured report."""
    CHECKS.clear()

    # Source file existence
    check_lab_runtime_exists()
    check_lab_runtime_event_codes()
    check_virtual_transport_exists()
    check_virtual_transport_event_codes()
    check_scenario_builder_exists()
    check_scenario_builder_event_codes()

    # Spec and evidence artifacts
    check_spec_contract_exists()
    check_evidence_exists()
    check_evidence_valid_json()
    check_evidence_required_fields()
    check_evidence_determinism_verified()

    total = len(CHECKS)
    passed = sum(1 for c in CHECKS if c["pass"])
    failed = total - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "bead_id": "bd-2ko",
        "title": "Deterministic lab runtime verification gate",
        "section": "10.11",
        "overall_pass": failed == 0,
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(CHECKS),
    }


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


def self_test() -> bool:
    """Validate internal checker logic using synthetic fixtures.

    Creates temporary file structures that should produce both PASS and FAIL
    verdicts, ensuring the checker correctly detects each condition.
    """
    import importlib
    import types
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

    # We need to temporarily override the module-level path constants to point
    # at our synthetic fixtures.  We do this by monkey-patching the globals,
    # running the checks, and then restoring.
    original_paths = {
        "LAB_RUNTIME_RS": LAB_RUNTIME_RS,
        "VIRTUAL_TRANSPORT_RS": VIRTUAL_TRANSPORT_RS,
        "SCENARIO_BUILDER_RS": SCENARIO_BUILDER_RS,
        "SPEC_CONTRACT": SPEC_CONTRACT,
        "EVIDENCE_JSON": EVIDENCE_JSON,
    }

    this_module = sys.modules[__name__]
    all_ok = True

    # ---- Test 1: All files present and valid -> PASS ----
    with tempfile.TemporaryDirectory(prefix="bd-2ko-selftest-") as tmp:
        tmp_path = Path(tmp)

        # Create synthetic lab_runtime.rs with all FN-LB codes.
        lab_src = "// synthetic lab_runtime.rs\n"
        for code in LAB_EVENT_CODES:
            lab_src += f'pub const EVT: &str = "{code}";\n'
        lab_rs = tmp_path / "lab_runtime.rs"
        lab_rs.write_text(lab_src, encoding="utf-8")

        # Create synthetic virtual_transport.rs with all VT codes.
        vt_src = "// synthetic virtual_transport.rs\n"
        for code in VT_EVENT_CODES:
            vt_src += f'pub const EVT: &str = "{code}";\n'
        vt_rs = tmp_path / "virtual_transport.rs"
        vt_rs.write_text(vt_src, encoding="utf-8")

        # Create synthetic scenario_builder.rs with all SB codes.
        sb_src = "// synthetic scenario_builder.rs\n"
        for code in SB_EVENT_CODES:
            sb_src += f'pub const EVT: &str = "{code}";\n'
        sb_rs = tmp_path / "scenario_builder.rs"
        sb_rs.write_text(sb_src, encoding="utf-8")

        # Create spec contract.
        spec = tmp_path / "bd-2ko_contract.md"
        spec.write_text("# bd-2ko contract\n", encoding="utf-8")

        # Create valid evidence JSON.
        evidence = {
            "bead_id": "bd-2ko",
            "section": "10.11",
            "scenarios_executed": 25,
            "interleavings_explored": 1000,
            "determinism_verified": True,
            "bugs_found": 0,
        }
        evidence_path = tmp_path / "verification_evidence.json"
        evidence_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")

        # Patch paths.
        setattr(this_module, "LAB_RUNTIME_RS", lab_rs)
        setattr(this_module, "VIRTUAL_TRANSPORT_RS", vt_rs)
        setattr(this_module, "SCENARIO_BUILDER_RS", sb_rs)
        setattr(this_module, "SPEC_CONTRACT", spec)
        setattr(this_module, "EVIDENCE_JSON", evidence_path)

        result_pass = run_checks()
        if result_pass["verdict"] != "PASS":
            print(
                "SELF-TEST FAIL: expected PASS with valid fixtures, "
                f"got {result_pass['verdict']}",
                file=sys.stderr,
            )
            for c in result_pass["checks"]:
                if not c["pass"]:
                    print(f"  failing check: {c['check']}: {c['detail']}", file=sys.stderr)
            all_ok = False

    # ---- Test 2: Missing files -> FAIL ----
    with tempfile.TemporaryDirectory(prefix="bd-2ko-selftest-") as tmp:
        tmp_path = Path(tmp)

        # Point all paths to non-existent locations.
        setattr(this_module, "LAB_RUNTIME_RS", tmp_path / "nonexistent.rs")
        setattr(this_module, "VIRTUAL_TRANSPORT_RS", tmp_path / "nonexistent2.rs")
        setattr(this_module, "SCENARIO_BUILDER_RS", tmp_path / "nonexistent3.rs")
        setattr(this_module, "SPEC_CONTRACT", tmp_path / "nonexistent.md")
        setattr(this_module, "EVIDENCE_JSON", tmp_path / "nonexistent.json")

        result_missing = run_checks()
        if result_missing["verdict"] != "FAIL":
            print(
                "SELF-TEST FAIL: expected FAIL with missing files, "
                f"got {result_missing['verdict']}",
                file=sys.stderr,
            )
            all_ok = False

    # ---- Test 3: Evidence with determinism_verified=false -> FAIL ----
    with tempfile.TemporaryDirectory(prefix="bd-2ko-selftest-") as tmp:
        tmp_path = Path(tmp)

        # Create all source files valid.
        lab_rs = tmp_path / "lab_runtime.rs"
        lab_src = "// synthetic\n"
        for code in LAB_EVENT_CODES:
            lab_src += f'pub const EVT: &str = "{code}";\n'
        lab_rs.write_text(lab_src, encoding="utf-8")

        vt_rs = tmp_path / "virtual_transport.rs"
        vt_src = "// synthetic\n"
        for code in VT_EVENT_CODES:
            vt_src += f'pub const EVT: &str = "{code}";\n'
        vt_rs.write_text(vt_src, encoding="utf-8")

        sb_rs = tmp_path / "scenario_builder.rs"
        sb_src = "// synthetic\n"
        for code in SB_EVENT_CODES:
            sb_src += f'pub const EVT: &str = "{code}";\n'
        sb_rs.write_text(sb_src, encoding="utf-8")

        spec = tmp_path / "bd-2ko_contract.md"
        spec.write_text("# bd-2ko contract\n", encoding="utf-8")

        evidence = {
            "bead_id": "bd-2ko",
            "section": "10.11",
            "scenarios_executed": 25,
            "interleavings_explored": 1000,
            "determinism_verified": False,
            "bugs_found": 3,
        }
        evidence_path = tmp_path / "verification_evidence.json"
        evidence_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")

        setattr(this_module, "LAB_RUNTIME_RS", lab_rs)
        setattr(this_module, "VIRTUAL_TRANSPORT_RS", vt_rs)
        setattr(this_module, "SCENARIO_BUILDER_RS", sb_rs)
        setattr(this_module, "SPEC_CONTRACT", spec)
        setattr(this_module, "EVIDENCE_JSON", evidence_path)

        result_det_false = run_checks()
        if result_det_false["verdict"] != "FAIL":
            print(
                "SELF-TEST FAIL: expected FAIL when determinism_verified=false, "
                f"got {result_det_false['verdict']}",
                file=sys.stderr,
            )
            all_ok = False

    # ---- Test 4: Malformed evidence JSON -> FAIL ----
    with tempfile.TemporaryDirectory(prefix="bd-2ko-selftest-") as tmp:
        tmp_path = Path(tmp)

        lab_rs = tmp_path / "lab_runtime.rs"
        lab_src = "// synthetic\n"
        for code in LAB_EVENT_CODES:
            lab_src += f'pub const EVT: &str = "{code}";\n'
        lab_rs.write_text(lab_src, encoding="utf-8")

        vt_rs = tmp_path / "virtual_transport.rs"
        vt_src = "// synthetic\n"
        for code in VT_EVENT_CODES:
            vt_src += f'pub const EVT: &str = "{code}";\n'
        vt_rs.write_text(vt_src, encoding="utf-8")

        sb_rs = tmp_path / "scenario_builder.rs"
        sb_src = "// synthetic\n"
        for code in SB_EVENT_CODES:
            sb_src += f'pub const EVT: &str = "{code}";\n'
        sb_rs.write_text(sb_src, encoding="utf-8")

        spec = tmp_path / "bd-2ko_contract.md"
        spec.write_text("# bd-2ko contract\n", encoding="utf-8")

        evidence_path = tmp_path / "verification_evidence.json"
        evidence_path.write_text("{invalid json", encoding="utf-8")

        setattr(this_module, "LAB_RUNTIME_RS", lab_rs)
        setattr(this_module, "VIRTUAL_TRANSPORT_RS", vt_rs)
        setattr(this_module, "SCENARIO_BUILDER_RS", sb_rs)
        setattr(this_module, "SPEC_CONTRACT", spec)
        setattr(this_module, "EVIDENCE_JSON", evidence_path)

        result_bad_json = run_checks()
        if result_bad_json["verdict"] != "FAIL":
            print(
                "SELF-TEST FAIL: expected FAIL with malformed JSON, "
                f"got {result_bad_json['verdict']}",
                file=sys.stderr,
            )
            all_ok = False

    # ---- Test 5: Evidence missing required fields -> FAIL ----
    with tempfile.TemporaryDirectory(prefix="bd-2ko-selftest-") as tmp:
        tmp_path = Path(tmp)

        lab_rs = tmp_path / "lab_runtime.rs"
        lab_src = "// synthetic\n"
        for code in LAB_EVENT_CODES:
            lab_src += f'pub const EVT: &str = "{code}";\n'
        lab_rs.write_text(lab_src, encoding="utf-8")

        vt_rs = tmp_path / "virtual_transport.rs"
        vt_src = "// synthetic\n"
        for code in VT_EVENT_CODES:
            vt_src += f'pub const EVT: &str = "{code}";\n'
        vt_rs.write_text(vt_src, encoding="utf-8")

        sb_rs = tmp_path / "scenario_builder.rs"
        sb_src = "// synthetic\n"
        for code in SB_EVENT_CODES:
            sb_src += f'pub const EVT: &str = "{code}";\n'
        sb_rs.write_text(sb_src, encoding="utf-8")

        spec = tmp_path / "bd-2ko_contract.md"
        spec.write_text("# bd-2ko contract\n", encoding="utf-8")

        # Evidence with missing fields (only bead_id).
        evidence_path = tmp_path / "verification_evidence.json"
        evidence_path.write_text(
            json.dumps({"bead_id": "bd-2ko"}), encoding="utf-8"
        )

        setattr(this_module, "LAB_RUNTIME_RS", lab_rs)
        setattr(this_module, "VIRTUAL_TRANSPORT_RS", vt_rs)
        setattr(this_module, "SCENARIO_BUILDER_RS", sb_rs)
        setattr(this_module, "SPEC_CONTRACT", spec)
        setattr(this_module, "EVIDENCE_JSON", evidence_path)

        result_missing_fields = run_checks()
        if result_missing_fields["verdict"] != "FAIL":
            print(
                "SELF-TEST FAIL: expected FAIL with missing evidence fields, "
                f"got {result_missing_fields['verdict']}",
                file=sys.stderr,
            )
            all_ok = False

    # Restore original paths.
    for attr, value in original_paths.items():
        setattr(this_module, attr, value)

    if all_ok:
        print("SELF-TEST OK: all 5 scenarios validated", file=sys.stderr)
    return all_ok


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> int:
    logger = configure_test_logging("check_deterministic_lab")
    parser = argparse.ArgumentParser(
        description="bd-2ko: Deterministic lab runtime verification gate (Section 10.11)"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output machine-readable JSON"
    )
    parser.add_argument(
        "--self-test", action="store_true", help="Run checker self-test"
    )
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        if args.json:
            payload = {
                "bead_id": "bd-2ko",
                "check": "self_test",
                "verdict": "PASS" if ok else "FAIL",
            }
            print(json.dumps(payload, indent=2))
        else:
            print(f"self_test verdict: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1

    report = run_checks()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for item in report["checks"]:
            status = "PASS" if item["pass"] else "FAIL"
            print(f"  [{status}] {item['check']}: {item['detail']}")
        print(
            f"\nbd-2ko verification: {report['verdict']} "
            f"({report['passed']}/{report['total']} checks pass)"
        )

    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
