#!/usr/bin/env python3
"""
ADR-001 Hybrid Baseline Strategy Verifier.

Validates that the ADR exists, contains all required rules,
has correct status, and is cross-referenced from the charter.

Usage:
    python3 scripts/verify_adr_hybrid_baseline.py [--json]

Exit codes:
    0 = PASS
    1 = FAIL
"""

import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone
from pathlib import Path

ADR_PATH = ROOT / "docs" / "adr" / "ADR-001-hybrid-baseline-strategy.md"
CHARTER_PATH = ROOT / "docs" / "PRODUCT_CHARTER.md"

# The 6 rules the ADR must codify
REQUIRED_RULES = {
    "no-clone": r"no.?bun.?first\s+clone|bun.?first\s+clone.*off.?charter",
    "spec-first": r"spec.?first.*extraction|essence\s+extraction",
    "native-impl": r"native.*implementation|implement.*natively.*franken_engine",
    "no-translation": r"line.?by.?line.*translation.*forbidden|line.?by.?line.*legacy.*translation",
    "fixture-oracle": r"fixture.?oracle|lockstep\s+oracle",
    "trust-native": r"trust.?native.*day\s+one|day\s+one.*trust",
}


def check_adr_exists() -> dict:
    """ADR-EXISTS: Check that the ADR file exists."""
    check = {"id": "ADR-EXISTS", "status": "PASS", "details": {}}
    if not ADR_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "ADR-001-hybrid-baseline-strategy.md not found"
    else:
        check["details"]["path"] = str(ADR_PATH.relative_to(ROOT))
        check["details"]["size_bytes"] = ADR_PATH.stat().st_size
    return check


def check_adr_status() -> dict:
    """ADR-STATUS: Check that ADR status is Accepted."""
    check = {"id": "ADR-STATUS", "status": "PASS", "details": {}}
    if not ADR_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "ADR file missing"
        return check

    text = ADR_PATH.read_text()
    if not re.search(r'\*\*Status\*\*:\s*Accepted', text):
        check["status"] = "FAIL"
        check["details"]["error"] = "ADR status is not 'Accepted'"
    else:
        check["details"]["status"] = "Accepted"
    return check


def check_adr_rules() -> dict:
    """ADR-RULES: Check that all 6 rules are present."""
    check = {"id": "ADR-RULES", "status": "PASS", "details": {"rules": {}}}
    if not ADR_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "ADR file missing"
        return check

    text = ADR_PATH.read_text().lower()
    for rule_name, pattern in REQUIRED_RULES.items():
        found = bool(re.search(pattern, text, re.IGNORECASE))
        check["details"]["rules"][rule_name] = found
        if not found:
            check["status"] = "FAIL"

    missing = [r for r, found in check["details"]["rules"].items() if not found]
    if missing:
        check["details"]["missing_rules"] = missing
    return check


def check_adr_references() -> dict:
    """ADR-REFS: Check that ADR references canonical plan sections."""
    check = {"id": "ADR-REFS", "status": "PASS", "details": {"references": []}}
    if not ADR_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "ADR file missing"
        return check

    text = ADR_PATH.read_text()
    expected_refs = [
        "PLAN_TO_CREATE_FRANKEN_NODE",
        "PRODUCT_CHARTER",
        "ENGINE_SPLIT_CONTRACT",
    ]
    for ref in expected_refs:
        found = ref in text
        check["details"]["references"].append({"name": ref, "found": found})
        if not found:
            check["status"] = "FAIL"

    return check


def check_charter_xref() -> dict:
    """ADR-CHARTER-XREF: Check that the charter cross-references the ADR."""
    check = {"id": "ADR-CHARTER-XREF", "status": "PASS", "details": {}}
    if not CHARTER_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "PRODUCT_CHARTER.md not found"
        return check

    text = CHARTER_PATH.read_text()
    if "ADR-001" not in text and "hybrid-baseline-strategy" not in text:
        check["status"] = "FAIL"
        check["details"]["error"] = "Charter does not reference ADR-001"
    else:
        check["details"]["cross_referenced"] = True
    return check


def main():
    logger = configure_test_logging("verify_adr_hybrid_baseline")
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        check_adr_exists(),
        check_adr_status(),
        check_adr_rules(),
        check_adr_references(),
        check_charter_xref(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "adr_hybrid_baseline_verification",
        "section": "10.1",
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
        print("=== ADR-001 Hybrid Baseline Verifier ===")
        print(f"Timestamp: {timestamp}")
        print()
        for c in checks:
            icon = "OK" if c["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {c['id']}")
            if c["status"] == "FAIL":
                details = c.get("details", {})
                if "error" in details:
                    print(f"       Error: {details['error']}")
                if "missing_rules" in details:
                    print(f"       Missing: {', '.join(details['missing_rules'])}")
        print()
        print(f"Checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
