#!/usr/bin/env python3
"""Verify bd-3gwi: Contribution-weighted intelligence access policy and reciprocity controls.

Checks that the ATC reciprocity infrastructure is correctly implemented:
Rust module present with required types, access tiers, event codes, invariants,
free-rider controls, grace period, exception paths, spec contract.

Usage:
    python scripts/check_atc_reciprocity.py
    python scripts/check_atc_reciprocity.py --json
    python scripts/check_atc_reciprocity.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

CHECKS: list[dict[str, Any]] = []

REQUIRED_TYPES = [
    "AccessTier",
    "ContributionMetrics",
    "AccessDecision",
    "AccessAuditEntry",
    "ReciprocityMatrix",
    "ReciprocityMatrixEntry",
    "ReciprocityConfig",
    "ReciprocityEngine",
]

REQUIRED_EVENT_CODES = [
    "ATC-RCP-001",
    "ATC-RCP-002",
    "ATC-RCP-003",
    "ATC-RCP-004",
    "ATC-RCP-005",
    "ATC-RCP-006",
    "ATC-RCP-007",
    "ATC-RCP-008",
    "ATC-RCP-009",
    "ATC-RCP-010",
    "ATC-RCP-ERR-001",
    "ATC-RCP-ERR-002",
]

REQUIRED_INVARIANTS = [
    "INV-ATC-RECIPROCITY-DETERMINISM",
    "INV-ATC-TIER-MONOTONE",
    "INV-ATC-FREERIDER-BOUND",
    "INV-ATC-EXCEPTION-AUDITED",
    "INV-ATC-GRACE-BOUNDED",
    "INV-ATC-ACCESS-LOGGED",
]

ACCESS_TIERS = ["Blocked", "Limited", "Standard", "Full"]


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    CHECKS.append(entry)
    return entry


def _safe_rel(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


def _read_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Checks: Rust implementation
# ---------------------------------------------------------------------------

def check_rust_module_exists() -> None:
    path = ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_reciprocity.rs"
    exists = path.is_file()
    _check("rust_module_exists", exists, _safe_rel(path) if exists else f"missing: {_safe_rel(path)}")


def check_federation_mod_registration() -> None:
    mod_rs = ROOT / "crates" / "franken-node" / "src" / "federation" / "mod.rs"
    src = _read_text(mod_rs)
    registered = "pub mod atc_reciprocity;" in src
    _check("federation_mod_registration", registered,
           "atc_reciprocity in federation/mod.rs" if registered else "NOT registered")


def check_required_types() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_reciprocity.rs")
    for type_name in REQUIRED_TYPES:
        found = type_name in src
        _check(f"type_{type_name}", found,
               f"{type_name} defined" if found else f"{type_name} missing")


def check_access_tiers() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_reciprocity.rs")
    for tier in ACCESS_TIERS:
        found = tier in src
        _check(f"access_tier_{tier}", found,
               f"{tier} tier defined" if found else f"{tier} tier missing")


def check_event_codes() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_reciprocity.rs")
    for code in REQUIRED_EVENT_CODES:
        found = f'"{code}"' in src
        _check(f"event_code_{code}", found,
               f"{code} defined" if found else f"{code} missing")


def check_invariants() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_reciprocity.rs")
    for inv in REQUIRED_INVARIANTS:
        found = f'"{inv}"' in src
        _check(f"invariant_{inv}", found,
               f"{inv} defined" if found else f"{inv} missing")


def check_freerider_controls() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_reciprocity.rs")
    has_ratio = "contribution_ratio" in src
    has_block = "Blocked" in src
    has_threshold = "limited_tier_min_ratio" in src
    passed = has_ratio and has_block and has_threshold
    _check("freerider_controls", passed,
           "contribution ratio + blocking + threshold" if passed else "freerider controls incomplete")


def check_grace_period() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_reciprocity.rs")
    has_grace = "grace_period_seconds" in src
    has_tier = "grace_period_tier" in src
    has_check = "grace_period_active" in src
    passed = has_grace and has_tier and has_check
    _check("grace_period", passed,
           "grace period with configurable tier" if passed else "grace period incomplete")


def check_exception_paths() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_reciprocity.rs")
    has_exception = "has_exception" in src
    has_reason = "exception_reason" in src
    has_audit = "EXCEPTION_ACTIVATED" in src
    passed = has_exception and has_reason and has_audit
    _check("exception_paths", passed,
           "exception paths with audit" if passed else "exception paths incomplete")


def check_audit_logging() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_reciprocity.rs")
    has_log = "audit_log" in src
    has_export = "export_audit_jsonl" in src
    has_hash = "content_hash" in src
    passed = has_log and has_export and has_hash
    _check("audit_logging", passed,
           "audit log with JSONL export and content hash" if passed else "audit logging incomplete")


def check_batch_evaluation() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_reciprocity.rs")
    has_batch = "fn evaluate_batch" in src
    has_matrix = "ReciprocityMatrix" in src
    passed = has_batch and has_matrix
    _check("batch_evaluation", passed,
           "batch evaluation with reciprocity matrix" if passed else "batch evaluation missing")


def check_inline_tests() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_reciprocity.rs")
    test_count = len(re.findall(r"#\[test\]", src))
    passed = test_count >= 15
    _check("inline_tests", passed, f"{test_count} inline tests (need >= 15)")


# ---------------------------------------------------------------------------
# Checks: Spec contract
# ---------------------------------------------------------------------------

def check_spec_contract() -> None:
    path = ROOT / "docs" / "specs" / "section_10_19" / "bd-3gwi_contract.md"
    exists = path.is_file()
    _check("spec_contract", exists, _safe_rel(path) if exists else f"missing: {_safe_rel(path)}")


def check_spec_invariants() -> None:
    src = _read_text(ROOT / "docs" / "specs" / "section_10_19" / "bd-3gwi_contract.md")
    for inv in REQUIRED_INVARIANTS:
        found = inv in src
        _check(f"spec_{inv}", found,
               f"{inv} in spec" if found else f"{inv} missing from spec")


def check_spec_event_codes() -> None:
    src = _read_text(ROOT / "docs" / "specs" / "section_10_19" / "bd-3gwi_contract.md")
    for code in REQUIRED_EVENT_CODES:
        found = code in src
        _check(f"spec_event_{code}", found,
               f"{code} in spec" if found else f"{code} missing from spec")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all_checks() -> list[dict[str, Any]]:
    CHECKS.clear()

    # Rust implementation
    check_rust_module_exists()
    check_federation_mod_registration()
    check_required_types()
    check_access_tiers()
    check_event_codes()
    check_invariants()
    check_freerider_controls()
    check_grace_period()
    check_exception_paths()
    check_audit_logging()
    check_batch_evaluation()
    check_inline_tests()

    # Spec contract
    check_spec_contract()
    check_spec_invariants()
    check_spec_event_codes()

    return CHECKS


def run_all() -> dict[str, Any]:
    checks = run_all_checks()
    total = len(checks)
    passed = sum(1 for c in checks if c["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-3gwi",
        "title": "Contribution-weighted intelligence access policy and reciprocity controls",
        "section": "10.19",
        "gate": False,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "overall_pass": failed == 0,
        "total": total,
        "passed": passed,
        "failed": failed,
        "required_types": REQUIRED_TYPES,
        "event_codes": REQUIRED_EVENT_CODES,
        "invariants": REQUIRED_INVARIANTS,
        "access_tiers": ACCESS_TIERS,
        "checks": checks,
    }


def self_test() -> bool:
    checks = run_all_checks()
    if not checks:
        print("SELF-TEST FAIL: no checks returned", file=sys.stderr)
        return False

    required_keys = {"check", "pass", "detail"}
    for entry in checks:
        if not isinstance(entry, dict) or not required_keys.issubset(entry.keys()):
            print(f"SELF-TEST FAIL: malformed entry: {entry}", file=sys.stderr)
            return False

    print(f"SELF-TEST OK: {len(checks)} checks returned", file=sys.stderr)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="bd-3gwi: ATC reciprocity verification")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(0 if self_test() else 1)

    output = run_all()

    if args.json:
        print(json.dumps(output, indent=2))
    else:
        print(
            f"\n  ATC Reciprocity: {'PASS' if output['overall_pass'] else 'FAIL'} "
            f"({output['passed']}/{output['total']})\n"
        )
        for entry in output["checks"]:
            mark = "+" if entry["pass"] else "x"
            print(f"  [{mark}] {entry['check']}: {entry['detail']}")

    sys.exit(0 if output["overall_pass"] else 1)


if __name__ == "__main__":
    main()
