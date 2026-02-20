#!/usr/bin/env python3
"""
Compatibility Mode Selection Policy Verifier.

Validates that COMPATIBILITY_MODE_POLICY.md exists, contains all 3 modes,
specifies the default, and covers all 4 bands per mode.

Usage:
    python3 scripts/check_compat_modes.py [--json]

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
POLICY_PATH = ROOT / "docs" / "COMPATIBILITY_MODE_POLICY.md"

REQUIRED_MODES = ["strict", "balanced", "legacy-risky"]
REQUIRED_BANDS = ["core", "high-value", "edge", "unsafe"]


def check_policy_exists() -> dict:
    """MODE-EXISTS: Check that COMPATIBILITY_MODE_POLICY.md exists."""
    check = {"id": "MODE-EXISTS", "status": "PASS", "details": {}}
    if not POLICY_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "docs/COMPATIBILITY_MODE_POLICY.md not found"
    else:
        check["details"]["path"] = str(POLICY_PATH.relative_to(ROOT))
    return check


def check_modes_defined() -> dict:
    """MODE-DEFINED: Check all 3 modes are defined."""
    check = {"id": "MODE-DEFINED", "status": "PASS", "details": {"modes": {}}}
    if not POLICY_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = POLICY_PATH.read_text().lower()
    for mode in REQUIRED_MODES:
        found = bool(re.search(rf'`{re.escape(mode)}`\s+mode', text))
        check["details"]["modes"][mode] = found
        if not found:
            check["status"] = "FAIL"

    return check


def check_default_mode() -> dict:
    """MODE-DEFAULT: Check that balanced is documented as default."""
    check = {"id": "MODE-DEFAULT", "status": "PASS", "details": {}}
    if not POLICY_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = POLICY_PATH.read_text().lower()
    if "default" in text and "balanced" in text:
        check["details"]["default_mode"] = "balanced"
    else:
        check["status"] = "FAIL"
        check["details"]["error"] = "Default mode (balanced) not documented"
    return check


def check_band_coverage() -> dict:
    """MODE-BANDS: Check each mode covers all 4 bands."""
    check = {"id": "MODE-BANDS", "status": "PASS", "details": {"coverage": {}}}
    if not POLICY_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = POLICY_PATH.read_text()
    for mode in REQUIRED_MODES:
        # Find mode section
        pattern = rf'###\s+\d+\.\d+\s+`{re.escape(mode)}`.*?(?=###\s+\d+\.\d+|## \d+\.|\Z)'
        m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        bands_found = {}
        if m:
            section = m.group(0).lower()
            for band in REQUIRED_BANDS:
                bands_found[band] = f'`{band}`' in section
        else:
            for band in REQUIRED_BANDS:
                bands_found[band] = False

        check["details"]["coverage"][mode] = bands_found
        if not all(bands_found.values()):
            check["status"] = "FAIL"

    return check


def check_unsafe_opt_in() -> dict:
    """MODE-UNSAFE: Check legacy-risky documents unsafe opt-in requirement."""
    check = {"id": "MODE-UNSAFE", "status": "PASS", "details": {}}
    if not POLICY_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = POLICY_PATH.read_text().lower()
    has_opt_in = "opt-in" in text or "opt_in" in text
    has_unsafe_gate = "policy gate" in text or "policy-gate" in text
    check["details"]["opt_in_documented"] = has_opt_in
    check["details"]["policy_gate_documented"] = has_unsafe_gate

    if not has_opt_in:
        check["status"] = "FAIL"
        check["details"]["error"] = "Unsafe opt-in not documented"
    return check


def check_bands_reference() -> dict:
    """MODE-BANDS-REF: Check policy references COMPATIBILITY_BANDS.md."""
    check = {"id": "MODE-BANDS-REF", "status": "PASS", "details": {}}
    if not POLICY_PATH.exists():
        check["status"] = "FAIL"
        return check

    text = POLICY_PATH.read_text()
    if "COMPATIBILITY_BANDS" not in text:
        check["status"] = "FAIL"
        check["details"]["error"] = "Missing reference to COMPATIBILITY_BANDS.md"
    else:
        check["details"]["bands_referenced"] = True
    return check


def main():
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        check_policy_exists(),
        check_modes_defined(),
        check_default_mode(),
        check_band_coverage(),
        check_unsafe_opt_in(),
        check_bands_reference(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "compatibility_mode_verification",
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
        print("=== Compatibility Mode Policy Verifier ===")
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
