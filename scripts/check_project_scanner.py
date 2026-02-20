#!/usr/bin/env python3
"""
Project Scanner Verifier.

Runs self-test and validates scanner infrastructure.

Usage:
    python3 scripts/check_project_scanner.py [--json]
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import project_scanner as scanner


def check_scanner_exists() -> dict:
    check = {"id": "SCANNER-EXISTS", "status": "PASS", "details": {}}
    scanner_path = ROOT / "scripts" / "project_scanner.py"
    schema_path = ROOT / "schemas" / "project_scan_report.schema.json"
    check["details"]["scanner"] = scanner_path.exists()
    check["details"]["schema"] = schema_path.exists()
    if not scanner_path.exists() or not schema_path.exists():
        check["status"] = "FAIL"
    return check


def check_api_patterns() -> dict:
    check = {"id": "SCANNER-PATTERNS", "status": "PASS", "details": {}}
    check["details"]["api_pattern_count"] = len(scanner.API_PATTERNS)
    check["details"]["unsafe_pattern_count"] = len(scanner.UNSAFE_PATTERNS)
    if len(scanner.API_PATTERNS) < 10:
        check["status"] = "FAIL"
    if len(scanner.UNSAFE_PATTERNS) < 3:
        check["status"] = "FAIL"
    return check


def check_registry_integration() -> dict:
    check = {"id": "SCANNER-REGISTRY", "status": "PASS", "details": {}}
    registry = scanner.load_registry()
    check["details"]["registry_entries"] = len(registry)
    if len(registry) < 1:
        check["status"] = "FAIL"
    return check


def check_self_test() -> dict:
    check = {"id": "SCANNER-SELFTEST", "status": "PASS", "details": {}}
    result = scanner.self_test()
    check["details"]["self_test_verdict"] = result["verdict"]
    check["details"]["apis_detected"] = result["sample_report"]["summary"]["total_apis_detected"]
    if result["verdict"] != "PASS":
        check["status"] = "FAIL"
    return check


def check_risk_classifier() -> dict:
    check = {"id": "SCANNER-RISK", "status": "PASS", "details": {}}
    tests = [
        (scanner.classify_risk("core", "native"), "low"),
        (scanner.classify_risk("core", "stub"), "medium"),
        (scanner.classify_risk("high-value", "stub"), "high"),
        (scanner.classify_risk(None, None, is_unsafe=True), "critical"),
    ]
    check["details"]["risk_tests"] = [{"expected": e, "got": g, "ok": g == e} for g, e in tests]
    if not all(g == e for g, e in tests):
        check["status"] = "FAIL"
    return check


def main():
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        check_scanner_exists(),
        check_api_patterns(),
        check_registry_integration(),
        check_self_test(),
        check_risk_classifier(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "project_scanner_verification",
        "section": "10.3",
        "verdict": verdict,
        "timestamp": timestamp,
        "checks": checks,
        "summary": {"total_checks": len(checks), "passing_checks": len(checks) - len(failing), "failing_checks": len(failing)},
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Project Scanner Verifier ===")
        print(f"Timestamp: {timestamp}\n")
        for c in checks:
            print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
        print(f"\nChecks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
