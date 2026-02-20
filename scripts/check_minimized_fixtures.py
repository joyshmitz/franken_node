#!/usr/bin/env python3
"""
Minimized Divergence Fixture Verifier.

Validates that the minimized fixture spec exists, the directory is set up,
and the design covers all required strategies.

Usage:
    python3 scripts/check_minimized_fixtures.py [--json]

Exit codes:
    0 = PASS
    1 = FAIL
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = ROOT / "docs" / "MINIMIZED_FIXTURE_SPEC.md"
FIXTURES_DIR = ROOT / "docs" / "fixtures" / "minimized"
FIXTURE_SCHEMA = ROOT / "schemas" / "compatibility_fixture.schema.json"

REQUIRED_STRATEGIES = ["input reduction", "scope isolation", "output extraction"]


def check_spec_exists() -> dict:
    """MIN-SPEC: Check spec document exists."""
    check = {"id": "MIN-SPEC", "status": "PASS", "details": {}}
    if not SPEC_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "MINIMIZED_FIXTURE_SPEC.md not found"
    else:
        check["details"]["path"] = str(SPEC_PATH.relative_to(ROOT))
    return check


def check_dir_exists() -> dict:
    """MIN-DIR: Check minimized fixtures directory exists."""
    check = {"id": "MIN-DIR", "status": "PASS", "details": {}}
    if not FIXTURES_DIR.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "docs/fixtures/minimized/ not found"
    else:
        check["details"]["path"] = str(FIXTURES_DIR.relative_to(ROOT))
    return check


def check_strategies() -> dict:
    """MIN-STRATEGIES: Check all minimization strategies are documented."""
    check = {"id": "MIN-STRATEGIES", "status": "PASS", "details": {"strategies": {}}}
    if not SPEC_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = SPEC_PATH.read_text().lower()
    for strategy in REQUIRED_STRATEGIES:
        found = strategy in text
        check["details"]["strategies"][strategy] = found
        if not found:
            check["status"] = "FAIL"

    return check


def check_fixture_format() -> dict:
    """MIN-FORMAT: Check generated fixture format is documented."""
    check = {"id": "MIN-FORMAT", "status": "PASS", "details": {}}
    if not SPEC_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = SPEC_PATH.read_text()
    has_schema_ref = "compatibility_fixture" in text or "fixture schema" in text.lower()
    has_extra_fields = "minimized_from" in text and "divergence_id" in text
    check["details"]["schema_referenced"] = has_schema_ref
    check["details"]["extra_fields_documented"] = has_extra_fields

    if not (has_schema_ref and has_extra_fields):
        check["status"] = "FAIL"
        check["details"]["error"] = "Generated fixture format incomplete"
    return check


def check_integration() -> dict:
    """MIN-INTEGRATION: Check integration with L1 runner and divergence ledger."""
    check = {"id": "MIN-INTEGRATION", "status": "PASS", "details": {}}
    if not SPEC_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = SPEC_PATH.read_text()
    has_l1 = "L1" in text or "lockstep" in text.lower()
    has_ledger = "divergence" in text.lower() and "ledger" in text.lower()
    check["details"]["l1_integration"] = has_l1
    check["details"]["ledger_integration"] = has_ledger

    if not (has_l1 and has_ledger):
        check["status"] = "FAIL"
    return check


def main():
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        check_spec_exists(),
        check_dir_exists(),
        check_strategies(),
        check_fixture_format(),
        check_integration(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "minimized_fixtures_verification",
        "section": "10.2",
        "verdict": verdict,
        "timestamp": timestamp,
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": sum(1 for c in checks if c["status"] == "PASS"),
            "failing_checks": len(failing),
        },
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Minimized Fixture Verifier ===")
        print(f"Timestamp: {timestamp}")
        print()
        for c in checks:
            icon = "OK" if c["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {c['id']}")
        print()
        print(f"Checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
