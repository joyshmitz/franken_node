#!/usr/bin/env python3
"""
Compatibility Dashboard Spec Verifier.

Usage:
    python3 scripts/check_compat_dashboard.py [--json]
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = ROOT / "docs" / "COMPAT_DASHBOARD_SPEC.md"
SCHEMA_PATH = ROOT / "schemas" / "compat_dashboard.schema.json"

REQUIRED_VIEWS = ["by api family", "by band", "trend", "regressions"]


def check_spec_exists() -> dict:
    check = {"id": "DASH-SPEC", "status": "PASS", "details": {}}
    if not SPEC_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "COMPAT_DASHBOARD_SPEC.md not found"
    return check


def check_schema_exists() -> dict:
    check = {"id": "DASH-SCHEMA", "status": "PASS", "details": {}}
    if not SCHEMA_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "Schema not found"
    else:
        try:
            data = json.loads(SCHEMA_PATH.read_text())
            check["details"]["required_fields"] = data.get("required", [])
        except json.JSONDecodeError:
            check["status"] = "FAIL"
    return check


def check_views() -> dict:
    check = {"id": "DASH-VIEWS", "status": "PASS", "details": {"views": {}}}
    if not SPEC_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = SPEC_PATH.read_text().lower()
    for view in REQUIRED_VIEWS:
        found = view in text
        check["details"]["views"][view] = found
        if not found:
            check["status"] = "FAIL"
    return check


def check_data_sources() -> dict:
    check = {"id": "DASH-SOURCES", "status": "PASS", "details": {}}
    if not SPEC_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = SPEC_PATH.read_text()
    has_registry = "COMPATIBILITY_REGISTRY" in text
    has_ledger = "DIVERGENCE_LEDGER" in text
    check["details"]["registry_referenced"] = has_registry
    check["details"]["ledger_referenced"] = has_ledger
    if not (has_registry and has_ledger):
        check["status"] = "FAIL"
    return check


def check_ci_integration() -> dict:
    check = {"id": "DASH-CI", "status": "PASS", "details": {}}
    if not SPEC_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = SPEC_PATH.read_text().lower()
    has_ci = "ci" in text and "pipeline" in text
    has_gate = "release gate" in text or "release" in text and "block" in text
    check["details"]["ci_documented"] = has_ci
    check["details"]["gate_documented"] = has_gate
    if not has_ci:
        check["status"] = "FAIL"
    return check


def main():
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [check_spec_exists(), check_schema_exists(), check_views(), check_data_sources(), check_ci_integration()]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "compat_dashboard_verification", "section": "10.2", "verdict": verdict,
        "timestamp": timestamp, "checks": checks,
        "summary": {"total_checks": len(checks), "passing_checks": len(checks) - len(failing), "failing_checks": len(failing)},
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Compat Dashboard Verifier ===")
        print(f"Timestamp: {timestamp}\n")
        for c in checks:
            print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
        print(f"\nChecks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass\nVerdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
