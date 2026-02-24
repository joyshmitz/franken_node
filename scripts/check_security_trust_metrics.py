#!/usr/bin/env python3
"""Verify bd-wzjl: Security and trust co-metrics for benchmark suite.

Checks that security/trust co-metric infrastructure is correctly implemented:
Rust module with required types, 5 security + 5 trust categories, event codes,
invariants, gate behavior, spec contract.

Usage:
    python scripts/check_security_trust_metrics.py
    python scripts/check_security_trust_metrics.py --json
    python scripts/check_security_trust_metrics.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

CHECKS: list[dict[str, Any]] = []

REQUIRED_TYPES = [
    "SecurityMetricCategory",
    "TrustMetricCategory",
    "ConfidenceInterval",
    "MetricMeasurement",
    "MetricThreshold",
    "MetricGateResult",
    "CoMetricReport",
    "CoMetricConfig",
    "CoMetricEngine",
]

SECURITY_CATEGORIES = [
    "SECM-SANDBOX",
    "SECM-REVOCATION",
    "SECM-POLICY",
    "SECM-ATTESTATION",
    "SECM-QUARANTINE",
]

TRUST_CATEGORIES = [
    "TRUSTM-CARD",
    "TRUSTM-VEF",
    "TRUSTM-EPOCH",
    "TRUSTM-EVIDENCE",
    "TRUSTM-REPUTATION",
]

REQUIRED_EVENT_CODES = [
    "SECM-001", "SECM-002", "SECM-003", "SECM-004", "SECM-005",
    "SECM-006", "SECM-007", "SECM-008", "SECM-009", "SECM-010",
    "SECM-ERR-001", "SECM-ERR-002",
]

REQUIRED_INVARIANTS = [
    "INV-SECM-QUANTIFIED",
    "INV-SECM-DETERMINISTIC",
    "INV-SECM-THRESHOLDED",
    "INV-SECM-CONFIDENCE",
    "INV-SECM-VERSIONED",
    "INV-SECM-GATED",
]


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
    path = ROOT / "crates" / "franken-node" / "src" / "tools" / "security_trust_metrics.rs"
    exists = path.is_file()
    _check("rust_module_exists", exists, _safe_rel(path) if exists else f"missing: {_safe_rel(path)}")


def check_tools_mod_registration() -> None:
    mod_rs = ROOT / "crates" / "franken-node" / "src" / "tools" / "mod.rs"
    src = _read_text(mod_rs)
    registered = "pub mod security_trust_metrics;" in src
    _check("tools_mod_registration", registered,
           "security_trust_metrics in tools/mod.rs" if registered else "NOT registered")


def check_required_types() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "tools" / "security_trust_metrics.rs")
    for type_name in REQUIRED_TYPES:
        found = type_name in src
        _check(f"type_{type_name}", found,
               f"{type_name} defined" if found else f"{type_name} missing")


def check_security_categories() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "tools" / "security_trust_metrics.rs")
    for cat in SECURITY_CATEGORIES:
        found = f'"{cat}"' in src
        _check(f"security_category_{cat}", found,
               f"{cat} defined" if found else f"{cat} missing")


def check_trust_categories() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "tools" / "security_trust_metrics.rs")
    for cat in TRUST_CATEGORIES:
        found = f'"{cat}"' in src
        _check(f"trust_category_{cat}", found,
               f"{cat} defined" if found else f"{cat} missing")


def check_event_codes() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "tools" / "security_trust_metrics.rs")
    for code in REQUIRED_EVENT_CODES:
        found = f'"{code}"' in src
        _check(f"event_code_{code}", found,
               f"{code} defined" if found else f"{code} missing")


def check_invariants() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "tools" / "security_trust_metrics.rs")
    for inv in REQUIRED_INVARIANTS:
        found = f'"{inv}"' in src
        _check(f"invariant_{inv}", found,
               f"{inv} defined" if found else f"{inv} missing")


def check_gate_behavior() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "tools" / "security_trust_metrics.rs")
    has_threshold = "pass_threshold" in src
    has_overall = "overall_pass" in src
    has_require = "require_all_categories" in src
    passed = has_threshold and has_overall and has_require
    _check("gate_behavior", passed,
           "threshold + overall_pass + category requirements" if passed else "gate behavior incomplete")


def check_confidence_intervals() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "tools" / "security_trust_metrics.rs")
    has_ci = "ConfidenceInterval" in src
    has_lower = "lower" in src
    has_upper = "upper" in src
    has_level = "confidence_level" in src
    passed = has_ci and has_lower and has_upper and has_level
    _check("confidence_intervals", passed,
           "ConfidenceInterval with lower/upper/level" if passed else "confidence intervals incomplete")


def check_formula_versioning() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "tools" / "security_trust_metrics.rs")
    has_version = "SCORING_FORMULA_VERSION" in src
    has_field = "formula_version" in src
    passed = has_version and has_field
    _check("formula_versioning", passed,
           "scoring formula version constant and field" if passed else "versioning incomplete")


def check_content_hash() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "tools" / "security_trust_metrics.rs")
    has_hash = "content_hash" in src
    has_compute = "compute_hash" in src
    passed = has_hash and has_compute
    _check("content_hash", passed,
           "content hash with compute_hash" if passed else "content hash missing")


def check_inline_tests() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "tools" / "security_trust_metrics.rs")
    test_count = len(re.findall(r"#\[test\]", src))
    passed = test_count >= 15
    _check("inline_tests", passed, f"{test_count} inline tests (need >= 15)")


# ---------------------------------------------------------------------------
# Checks: Spec contract
# ---------------------------------------------------------------------------

def check_spec_contract() -> None:
    path = ROOT / "docs" / "specs" / "section_14" / "bd-wzjl_contract.md"
    exists = path.is_file()
    _check("spec_contract", exists, _safe_rel(path) if exists else f"missing: {_safe_rel(path)}")


def check_spec_security_categories() -> None:
    src = _read_text(ROOT / "docs" / "specs" / "section_14" / "bd-wzjl_contract.md")
    for cat in SECURITY_CATEGORIES:
        found = cat in src
        _check(f"spec_security_{cat}", found,
               f"{cat} in spec" if found else f"{cat} missing from spec")


def check_spec_trust_categories() -> None:
    src = _read_text(ROOT / "docs" / "specs" / "section_14" / "bd-wzjl_contract.md")
    for cat in TRUST_CATEGORIES:
        found = cat in src
        _check(f"spec_trust_{cat}", found,
               f"{cat} in spec" if found else f"{cat} missing from spec")


def check_spec_invariants() -> None:
    src = _read_text(ROOT / "docs" / "specs" / "section_14" / "bd-wzjl_contract.md")
    for inv in REQUIRED_INVARIANTS:
        found = inv in src
        _check(f"spec_{inv}", found,
               f"{inv} in spec" if found else f"{inv} missing from spec")


def check_spec_event_codes() -> None:
    src = _read_text(ROOT / "docs" / "specs" / "section_14" / "bd-wzjl_contract.md")
    for code in REQUIRED_EVENT_CODES:
        found = code in src
        _check(f"spec_event_{code}", found,
               f"{code} in spec" if found else f"{code} missing from spec")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all_checks() -> list[dict[str, Any]]:
    CHECKS.clear()

    check_rust_module_exists()
    check_tools_mod_registration()
    check_required_types()
    check_security_categories()
    check_trust_categories()
    check_event_codes()
    check_invariants()
    check_gate_behavior()
    check_confidence_intervals()
    check_formula_versioning()
    check_content_hash()
    check_inline_tests()

    check_spec_contract()
    check_spec_security_categories()
    check_spec_trust_categories()
    check_spec_invariants()
    check_spec_event_codes()

    return CHECKS


def run_all() -> dict[str, Any]:
    checks = run_all_checks()
    total = len(checks)
    passed = sum(1 for c in checks if c["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-wzjl",
        "title": "Security and trust co-metrics for benchmark suite",
        "section": "14",
        "gate": False,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "overall_pass": failed == 0,
        "total": total,
        "passed": passed,
        "failed": failed,
        "security_categories": SECURITY_CATEGORIES,
        "trust_categories": TRUST_CATEGORIES,
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
    logger = configure_test_logging("check_security_trust_metrics")
    parser = argparse.ArgumentParser(description="bd-wzjl: security/trust co-metrics verification")
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
            f"\n  Security/Trust Co-Metrics: {'PASS' if output['overall_pass'] else 'FAIL'} "
            f"({output['passed']}/{output['total']})\n"
        )
        for entry in output["checks"]:
            mark = "+" if entry["pass"] else "x"
            print(f"  [{mark}] {entry['check']}: {entry['detail']}")

    sys.exit(0 if output["overall_pass"] else 1)


if __name__ == "__main__":
    main()
