#!/usr/bin/env python3
"""
Implementation Governance Policy Verifier.

Validates that IMPLEMENTATION_GOVERNANCE.md exists, contains all required
rules, references ADR-001, and is cross-referenced from the charter.

Usage:
    python3 scripts/check_impl_governance.py [--json]

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

POLICY_PATH = ROOT / "docs" / "IMPLEMENTATION_GOVERNANCE.md"
CHARTER_PATH = ROOT / "docs" / "PRODUCT_CHARTER.md"
ADR_PATH = ROOT / "docs" / "adr" / "ADR-001-hybrid-baseline-strategy.md"

REQUIRED_RULES = {
    "no-translation": r"no\s+line.?by.?line|line.?by.?line.*translation.*must\s+not",
    "spec-refs": r"spec\s+references?\s+required",
    "fixture-refs": r"fixture\s+references?\s+required",
    "pr-format": r"pr\s+description\s+format",
}


def check_policy_exists() -> dict:
    """GOV-EXISTS: Check that the policy document exists."""
    check = {"id": "GOV-EXISTS", "status": "PASS", "details": {}}
    if not POLICY_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "IMPLEMENTATION_GOVERNANCE.md not found"
    else:
        check["details"]["path"] = str(POLICY_PATH.relative_to(ROOT))
        check["details"]["size_bytes"] = POLICY_PATH.stat().st_size
    return check


def check_policy_rules() -> dict:
    """GOV-RULES: Check that all 4 required rules are present."""
    check = {"id": "GOV-RULES", "status": "PASS", "details": {"rules": {}}}
    if not POLICY_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "Policy file missing"
        return check

    text = POLICY_PATH.read_text().lower()
    for rule_name, pattern in REQUIRED_RULES.items():
        found = bool(re.search(pattern, text, re.IGNORECASE))
        check["details"]["rules"][rule_name] = found
        if not found:
            check["status"] = "FAIL"

    missing = [r for r, found in check["details"]["rules"].items() if not found]
    if missing:
        check["details"]["missing_rules"] = missing
    return check


def check_adr_reference() -> dict:
    """GOV-ADR-REF: Check that policy references ADR-001."""
    check = {"id": "GOV-ADR-REF", "status": "PASS", "details": {}}
    if not POLICY_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "Policy file missing"
        return check

    text = POLICY_PATH.read_text()
    if "ADR-001" not in text:
        check["status"] = "FAIL"
        check["details"]["error"] = "Policy does not reference ADR-001"
    else:
        check["details"]["adr_referenced"] = True
    return check


def check_charter_xref() -> dict:
    """GOV-CHARTER-XREF: Check that charter cross-references the governance policy."""
    check = {"id": "GOV-CHARTER-XREF", "status": "PASS", "details": {}}
    if not CHARTER_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "PRODUCT_CHARTER.md not found"
        return check

    text = CHARTER_PATH.read_text()
    if "IMPLEMENTATION_GOVERNANCE" not in text:
        check["status"] = "FAIL"
        check["details"]["error"] = "Charter does not reference IMPLEMENTATION_GOVERNANCE.md"
    else:
        check["details"]["cross_referenced"] = True
    return check


def check_enforcement_section() -> dict:
    """GOV-ENFORCEMENT: Check that enforcement mechanisms are documented."""
    check = {"id": "GOV-ENFORCEMENT", "status": "PASS", "details": {}}
    if not POLICY_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "Policy file missing"
        return check

    text = POLICY_PATH.read_text()
    has_enforcement = "## 3. Enforcement" in text or "## Enforcement" in text
    has_ci_gate = "CI" in text and ("gate" in text.lower() or "check" in text.lower())
    has_review = "review" in text.lower() and "checklist" in text.lower()

    check["details"]["enforcement_section"] = has_enforcement
    check["details"]["ci_gate_documented"] = has_ci_gate
    check["details"]["review_checklist"] = has_review

    if not has_enforcement:
        check["status"] = "FAIL"
        check["details"]["error"] = "Missing enforcement section"
    return check


def main():
    logger = configure_test_logging("check_impl_governance")
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        check_policy_exists(),
        check_policy_rules(),
        check_adr_reference(),
        check_charter_xref(),
        check_enforcement_section(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "implementation_governance_verification",
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
        print("=== Implementation Governance Verifier ===")
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
