#!/usr/bin/env python3
"""
L1 Lockstep Runner Design Verifier.

Validates that the lockstep runner design document and configuration
schema exist with all required phases and fields.

Usage:
    python3 scripts/check_lockstep_runner.py [--json]

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
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
DESIGN_PATH = ROOT / "docs" / "L1_LOCKSTEP_RUNNER.md"
CONFIG_SCHEMA_PATH = ROOT / "schemas" / "lockstep_runner_config.schema.json"
FIXTURE_SCHEMA_PATH = ROOT / "schemas" / "compatibility_fixture.schema.json"

REQUIRED_PHASES = [
    "fixture loading",
    "runtime execution",
    "result canonicalization",
    "delta detection",
    "report generation",
]


def check_design_exists() -> dict:
    """L1-DESIGN: Check design document exists."""
    check = {"id": "L1-DESIGN", "status": "PASS", "details": {}}
    if not DESIGN_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "L1_LOCKSTEP_RUNNER.md not found"
    else:
        check["details"]["path"] = str(DESIGN_PATH.relative_to(ROOT))
    return check


def check_config_schema() -> dict:
    """L1-CONFIG: Check config schema exists and is valid."""
    check = {"id": "L1-CONFIG", "status": "PASS", "details": {}}
    if not CONFIG_SCHEMA_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "Config schema not found"
        return check

    try:
        data = json.loads(CONFIG_SCHEMA_PATH.read_text())
        required = data.get("required", [])
        check["details"]["required_fields"] = required
        if "runtimes" not in required:
            check["status"] = "FAIL"
            check["details"]["error"] = "Schema missing 'runtimes' in required"
    except json.JSONDecodeError:
        check["status"] = "FAIL"
        check["details"]["error"] = "Invalid JSON in schema"
    return check


def check_phases_documented() -> dict:
    """L1-PHASES: Check all 5 phases are documented."""
    check = {"id": "L1-PHASES", "status": "PASS", "details": {"phases": {}}}
    if not DESIGN_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = DESIGN_PATH.read_text().lower()
    for phase in REQUIRED_PHASES:
        found = phase in text
        check["details"]["phases"][phase] = found
        if not found:
            check["status"] = "FAIL"

    missing = [p for p, found in check["details"]["phases"].items() if not found]
    if missing:
        check["details"]["missing_phases"] = missing
    return check


def check_delta_format() -> dict:
    """L1-DELTA: Check delta report format is documented."""
    check = {"id": "L1-DELTA", "status": "PASS", "details": {}}
    if not DESIGN_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = DESIGN_PATH.read_text()
    has_report = "delta report" in text.lower() or "report format" in text.lower()
    has_json = "schema_version" in text and "divergences" in text
    check["details"]["report_documented"] = has_report
    check["details"]["json_format"] = has_json

    if not (has_report and has_json):
        check["status"] = "FAIL"
        check["details"]["error"] = "Delta report format not fully documented"
    return check


def check_release_gating() -> dict:
    """L1-GATING: Check release gating rules are documented."""
    check = {"id": "L1-GATING", "status": "PASS", "details": {}}
    if not DESIGN_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = DESIGN_PATH.read_text().lower()
    has_core_block = "core" in text and "block" in text
    has_mode_ref = "strict" in text or "balanced" in text
    check["details"]["core_blocks_release"] = has_core_block
    check["details"]["mode_integration"] = has_mode_ref

    if not has_core_block:
        check["status"] = "FAIL"
        check["details"]["error"] = "Core band release blocking not documented"
    return check


def main():
    logger = configure_test_logging("check_lockstep_runner")
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        check_design_exists(),
        check_config_schema(),
        check_phases_documented(),
        check_delta_format(),
        check_release_gating(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "lockstep_runner_verification",
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
        print("=== L1 Lockstep Runner Verifier ===")
        print(f"Timestamp: {timestamp}")
        print()
        for c in checks:
            icon = "OK" if c["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {c['id']}")
            if c["status"] == "FAIL":
                details = c.get("details", {})
                if "error" in details:
                    print(f"       Error: {details['error']}")
        print()
        print(f"Checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
