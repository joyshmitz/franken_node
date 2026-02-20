#!/usr/bin/env python3
"""
L2 Engine-Boundary Oracle Verifier.

Validates that the L2 oracle design document exists, covers all required
boundary aspects, and documents release gate linkage.

Usage:
    python3 scripts/check_l2_oracle.py [--json]

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
DESIGN_PATH = ROOT / "docs" / "L2_ENGINE_BOUNDARY_ORACLE.md"
SPLIT_CONTRACT = ROOT / "docs" / "ENGINE_SPLIT_CONTRACT.md"

REQUIRED_SECTIONS = [
    "boundary definition",
    "semantic checks",
    "release gate",
    "trust gate",
]


def check_design_exists() -> dict:
    """L2-DESIGN: Check L2 oracle design document exists."""
    check = {"id": "L2-DESIGN", "status": "PASS", "details": {}}
    if not DESIGN_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "L2_ENGINE_BOUNDARY_ORACLE.md not found"
    else:
        check["details"]["path"] = str(DESIGN_PATH.relative_to(ROOT))
    return check


def check_boundary_coverage() -> dict:
    """L2-BOUNDARY: Check all boundary aspects are documented."""
    check = {"id": "L2-BOUNDARY", "status": "PASS", "details": {"sections": {}}}
    if not DESIGN_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = DESIGN_PATH.read_text().lower()
    for section in REQUIRED_SECTIONS:
        found = section in text
        check["details"]["sections"][section] = found
        if not found:
            check["status"] = "FAIL"

    return check


def check_always_blocks() -> dict:
    """L2-BLOCKS: Check L2 failures always block release."""
    check = {"id": "L2-BLOCKS", "status": "PASS", "details": {}}
    if not DESIGN_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = DESIGN_PATH.read_text().lower()
    has_always_block = "always block" in text and "release" in text
    has_non_negotiable = "non-negotiable" in text or "no workaround" in text or "no exception" in text
    check["details"]["always_blocks"] = has_always_block
    check["details"]["non_negotiable"] = has_non_negotiable

    if not has_always_block:
        check["status"] = "FAIL"
        check["details"]["error"] = "L2 always-blocks-release not documented"
    return check


def check_split_reference() -> dict:
    """L2-SPLIT-REF: Check L2 references ENGINE_SPLIT_CONTRACT."""
    check = {"id": "L2-SPLIT-REF", "status": "PASS", "details": {}}
    if not DESIGN_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = DESIGN_PATH.read_text()
    if "ENGINE_SPLIT_CONTRACT" not in text:
        check["status"] = "FAIL"
        check["details"]["error"] = "Missing ENGINE_SPLIT_CONTRACT reference"
    else:
        check["details"]["split_referenced"] = True
    return check


def check_l1_complement() -> dict:
    """L2-L1-COMPLEMENT: Check L2 documents complement to L1."""
    check = {"id": "L2-L1-COMPLEMENT", "status": "PASS", "details": {}}
    if not DESIGN_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = DESIGN_PATH.read_text().lower()
    has_l1_ref = "l1" in text
    has_both_required = "both" in text and ("required" in text or "must pass" in text or "neither replaces" in text)
    check["details"]["l1_referenced"] = has_l1_ref
    check["details"]["both_required"] = has_both_required

    if not (has_l1_ref and has_both_required):
        check["status"] = "FAIL"
    return check


def main():
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        check_design_exists(),
        check_boundary_coverage(),
        check_always_blocks(),
        check_split_reference(),
        check_l1_complement(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "l2_oracle_verification",
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
        print("=== L2 Engine-Boundary Oracle Verifier ===")
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
