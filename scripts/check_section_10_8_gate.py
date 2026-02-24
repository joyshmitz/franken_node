#!/usr/bin/env python3
"""Section 10.8 verification gate: Operational Readiness.

Aggregates evidence from all 6 section beads and produces a gate verdict.

Usage:
    python scripts/check_section_10_8_gate.py          # human-readable
    python scripts/check_section_10_8_gate.py --json    # machine-readable
    python scripts/check_section_10_8_gate.py --self-test
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

# Section 10.8 beads
SECTION_BEADS = [
    ("bd-tg2", "Implement fleet control API for quarantine/revocation operations"),
    ("bd-3o6", "Adopt canonical structured observability + stable error taxonomy contracts"),
    ("bd-k6o", "Implement deterministic safe-mode startup and operation flags"),
    ("bd-f2y", "Implement incident bundle retention and export policy"),
    ("bd-nr4", "Implement operator runbooks for high-severity trust incidents"),
    ("bd-3m6", "Implement disaster-recovery drills for control-plane failures"),
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


def _safe_relative(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


def _evidence_pass(data: dict[str, Any]) -> bool:
    """Check if evidence data indicates PASS. Handles multiple formats."""
    if data.get("verdict") == "PASS":
        return True
    if data.get("overall_pass") is True:
        return True
    if str(data.get("status", "")).lower() == "pass":
        return True
    return False


# ---------------------------------------------------------------------------
# Bead evidence checks
# ---------------------------------------------------------------------------


def check_bead_evidence(bead_id: str, title: str) -> dict[str, Any]:
    """Check that a bead has evidence with PASS verdict."""
    evidence_path = ROOT / "artifacts" / "section_10_8" / bead_id / "verification_evidence.json"
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
    """Check that a bead has a verification summary."""
    summary_path = ROOT / "artifacts" / "section_10_8" / bead_id / "verification_summary.md"
    exists = summary_path.is_file()
    return _check(
        f"summary_{bead_id}",
        exists,
        f"exists: {_safe_relative(summary_path)}" if exists else f"missing: {_safe_relative(summary_path)}",
    )


# ---------------------------------------------------------------------------
# Aggregate checks
# ---------------------------------------------------------------------------


def check_all_evidence_present() -> dict[str, Any]:
    count = 0
    for bead_id, _ in SECTION_BEADS:
        evidence_path = ROOT / "artifacts" / "section_10_8" / bead_id / "verification_evidence.json"
        if evidence_path.is_file():
            count += 1
    passed = count == len(SECTION_BEADS)
    return _check(
        "all_evidence_present",
        passed,
        f"{count}/{len(SECTION_BEADS)} beads have evidence",
    )


def check_all_verdicts_pass() -> dict[str, Any]:
    pass_count = 0
    fail_list: list[str] = []
    for bead_id, _ in SECTION_BEADS:
        evidence_path = ROOT / "artifacts" / "section_10_8" / bead_id / "verification_evidence.json"
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


# ---------------------------------------------------------------------------
# Section-specific artifact checks
# ---------------------------------------------------------------------------


def check_fleet_control_impl() -> dict[str, Any]:
    path = ROOT / "crates" / "franken-node" / "src" / "api" / "fleet_quarantine.rs"
    exists = path.is_file()
    return _check("fleet_control_impl", exists, f"exists: {_safe_relative(path)}" if exists else "missing")


def check_fleet_control_routes() -> dict[str, Any]:
    path = ROOT / "crates" / "franken-node" / "src" / "api" / "fleet_control_routes.rs"
    exists = path.is_file()
    return _check("fleet_control_routes", exists, f"exists: {_safe_relative(path)}" if exists else "missing")


def check_safe_mode_impl() -> dict[str, Any]:
    path = ROOT / "crates" / "franken-node" / "src" / "runtime" / "safe_mode.rs"
    exists = path.is_file()
    return _check("safe_mode_impl", exists, f"exists: {_safe_relative(path)}" if exists else "missing")


def check_observability_impl() -> dict[str, Any]:
    path = ROOT / "crates" / "franken-node" / "src" / "observability" / "mod.rs"
    exists = path.is_file()
    return _check("observability_impl", exists, f"exists: {_safe_relative(path)}" if exists else "missing")


def check_incident_retention_impl() -> dict[str, Any]:
    path = ROOT / "crates" / "franken-node" / "src" / "connector" / "incident_bundle_retention.rs"
    exists = path.is_file()
    return _check("incident_retention_impl", exists, f"exists: {_safe_relative(path)}" if exists else "missing")


def check_safe_mode_policy() -> dict[str, Any]:
    path = ROOT / "docs" / "policy" / "safe_mode_operations.md"
    exists = path.is_file()
    return _check("safe_mode_policy", exists, f"exists: {_safe_relative(path)}" if exists else "missing")


def check_observability_policy() -> dict[str, Any]:
    path = ROOT / "docs" / "policy" / "structured_observability.md"
    exists = path.is_file()
    return _check("observability_policy", exists, f"exists: {_safe_relative(path)}" if exists else "missing")


def check_incident_retention_policy() -> dict[str, Any]:
    path = ROOT / "docs" / "policy" / "incident_bundle_retention.md"
    exists = path.is_file()
    return _check("incident_retention_policy", exists, f"exists: {_safe_relative(path)}" if exists else "missing")


def check_fleet_quarantine_policy() -> dict[str, Any]:
    path = ROOT / "docs" / "policy" / "fleet_quarantine_operations.md"
    exists = path.is_file()
    return _check("fleet_quarantine_policy", exists, f"exists: {_safe_relative(path)}" if exists else "missing")


# ---------------------------------------------------------------------------
# Spec file checks
# ---------------------------------------------------------------------------


def check_spec_files() -> list[dict[str, Any]]:
    checks = []
    for bead_id, _ in SECTION_BEADS:
        spec_path = ROOT / "docs" / "specs" / "section_10_8" / f"{bead_id}_contract.md"
        exists = spec_path.is_file()
        checks.append(_check(
            f"spec_{bead_id}",
            exists,
            f"exists: {_safe_relative(spec_path)}" if exists else f"missing: {_safe_relative(spec_path)}",
        ))
    return checks


# ---------------------------------------------------------------------------
# Cross-bead integration checks
# ---------------------------------------------------------------------------


def check_fleet_event_codes() -> dict[str, Any]:
    """Verify fleet control has structured event codes."""
    path = ROOT / "crates" / "franken-node" / "src" / "api" / "fleet_quarantine.rs"
    if not path.is_file():
        return _check("fleet_event_codes", False, "impl file missing")
    src = path.read_text()
    codes = ["FLEET-001", "FLEET-002", "FLEET-003", "FLEET-004", "FLEET-005"]
    found = sum(1 for c in codes if c in src)
    return _check("fleet_event_codes", found == len(codes), f"{found}/{len(codes)} event codes")


def check_safe_mode_event_codes() -> dict[str, Any]:
    """Verify safe-mode has structured event codes."""
    path = ROOT / "crates" / "franken-node" / "src" / "runtime" / "safe_mode.rs"
    if not path.is_file():
        return _check("safe_mode_event_codes", False, "impl file missing")
    src = path.read_text()
    codes = ["SMO-001", "SMO-002", "SMO-003", "SMO-004"]
    found = sum(1 for c in codes if c in src)
    return _check("safe_mode_event_codes", found == len(codes), f"{found}/{len(codes)} event codes")


def check_fleet_invariants() -> dict[str, Any]:
    """Verify fleet control invariants are declared."""
    path = ROOT / "crates" / "franken-node" / "src" / "api" / "fleet_quarantine.rs"
    if not path.is_file():
        return _check("fleet_invariants", False, "impl file missing")
    src = path.read_text()
    invs = ["INV-FLEET-ZONE-SCOPE", "INV-FLEET-RECEIPT", "INV-FLEET-CONVERGENCE",
            "INV-FLEET-SAFE-START", "INV-FLEET-ROLLBACK"]
    found = sum(1 for i in invs if i in src)
    return _check("fleet_invariants", found == len(invs), f"{found}/{len(invs)} invariants")


def check_safe_mode_invariants() -> dict[str, Any]:
    """Verify safe-mode invariants are declared."""
    path = ROOT / "crates" / "franken-node" / "src" / "runtime" / "safe_mode.rs"
    if not path.is_file():
        return _check("safe_mode_invariants", False, "impl file missing")
    src = path.read_text()
    has_inv = "INV-SMO" in src
    return _check("safe_mode_invariants", has_inv, "INV-SMO invariants found" if has_inv else "missing")


def check_fleet_unit_tests() -> dict[str, Any]:
    """Verify fleet quarantine has sufficient unit tests."""
    path = ROOT / "crates" / "franken-node" / "src" / "api" / "fleet_quarantine.rs"
    if not path.is_file():
        return _check("fleet_unit_tests", False, "impl file missing")
    src = path.read_text()
    test_count = src.count("#[test]")
    return _check("fleet_unit_tests", test_count >= 40, f"{test_count} tests")


def check_safe_mode_unit_tests() -> dict[str, Any]:
    """Verify safe-mode has sufficient unit tests."""
    path = ROOT / "crates" / "franken-node" / "src" / "runtime" / "safe_mode.rs"
    if not path.is_file():
        return _check("safe_mode_unit_tests", False, "impl file missing")
    src = path.read_text()
    test_count = src.count("#[test]")
    return _check("safe_mode_unit_tests", test_count >= 20, f"{test_count} tests")


def check_incident_retention_unit_tests() -> dict[str, Any]:
    """Verify incident bundle retention has unit tests."""
    path = ROOT / "crates" / "franken-node" / "src" / "connector" / "incident_bundle_retention.rs"
    if not path.is_file():
        return _check("incident_retention_unit_tests", False, "impl file missing")
    src = path.read_text()
    test_count = src.count("#[test]")
    return _check("incident_retention_unit_tests", test_count >= 10, f"{test_count} tests")


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------


def run_all_checks() -> list[dict[str, Any]]:
    RESULTS.clear()

    # Per-bead evidence checks
    for bead_id, title in SECTION_BEADS:
        check_bead_evidence(bead_id, title)

    # Per-bead summary checks
    for bead_id, _ in SECTION_BEADS:
        check_bead_summary(bead_id)

    # Aggregate checks
    check_all_evidence_present()
    check_all_verdicts_pass()

    # Spec file checks
    check_spec_files()

    # Key implementation checks
    check_fleet_control_impl()
    check_fleet_control_routes()
    check_safe_mode_impl()
    check_observability_impl()
    check_incident_retention_impl()

    # Policy document checks
    check_safe_mode_policy()
    check_observability_policy()
    check_incident_retention_policy()
    check_fleet_quarantine_policy()

    # Cross-bead integration checks
    check_fleet_event_codes()
    check_safe_mode_event_codes()
    check_fleet_invariants()
    check_safe_mode_invariants()
    check_fleet_unit_tests()
    check_safe_mode_unit_tests()
    check_incident_retention_unit_tests()

    return RESULTS


def run_all() -> dict[str, Any]:
    results = run_all_checks()
    total = len(results)
    passed = sum(1 for r in results if r["pass"])
    failed = total - passed
    overall = failed == 0
    return {
        "bead_id": "bd-1fi2",
        "title": "Section 10.8 verification gate: Operational Readiness",
        "section": "10.8",
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
    logger = configure_test_logging("check_section_10_8_gate")
    parser = argparse.ArgumentParser(description="Section 10.8 verification gate")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(0 if self_test() else 1)

    result = run_all()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n  Section 10.8 Gate: {'PASS' if result['verdict'] == 'PASS' else 'FAIL'} ({result['passed']}/{result['total']})\n")
        for r in result["checks"]:
            mark = "+" if r["pass"] else "x"
            print(f"  [{mark}] {r['check']}: {r['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
