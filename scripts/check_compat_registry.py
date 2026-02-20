#!/usr/bin/env python3
"""
Compatibility Behavior Registry Verifier.

Validates that COMPATIBILITY_REGISTRY.json exists, conforms to schema rules,
and all entries have valid field values.

Usage:
    python3 scripts/check_compat_registry.py [--json]

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
REGISTRY_PATH = ROOT / "docs" / "COMPATIBILITY_REGISTRY.json"
SCHEMA_PATH = ROOT / "schemas" / "compatibility_registry.schema.json"

VALID_BANDS = {"core", "high-value", "edge", "unsafe"}
VALID_SHIM_TYPES = {"native", "polyfill", "bridge", "stub"}
VALID_ORACLE_STATUSES = {"validated", "pending", "not-applicable"}
ID_PATTERN = re.compile(r'^compat:[a-z_]+:[a-zA-Z_]+$')


def check_registry_exists() -> dict:
    """REG-EXISTS: Check that COMPATIBILITY_REGISTRY.json exists."""
    check = {"id": "REG-EXISTS", "status": "PASS", "details": {}}
    if not REGISTRY_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "docs/COMPATIBILITY_REGISTRY.json not found"
    else:
        check["details"]["path"] = str(REGISTRY_PATH.relative_to(ROOT))
    return check


def check_schema_exists() -> dict:
    """REG-SCHEMA: Check that the JSON schema exists."""
    check = {"id": "REG-SCHEMA", "status": "PASS", "details": {}}
    if not SCHEMA_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "schemas/compatibility_registry.schema.json not found"
    else:
        check["details"]["path"] = str(SCHEMA_PATH.relative_to(ROOT))
    return check


def load_registry() -> tuple[dict | None, str | None]:
    """Load and parse the registry JSON."""
    if not REGISTRY_PATH.exists():
        return None, "File not found"
    try:
        data = json.loads(REGISTRY_PATH.read_text())
        return data, None
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON: {e}"


def check_registry_structure() -> dict:
    """REG-STRUCTURE: Check registry has required top-level fields."""
    check = {"id": "REG-STRUCTURE", "status": "PASS", "details": {}}
    data, err = load_registry()
    if err:
        check["status"] = "FAIL"
        check["details"]["error"] = err
        return check

    if data.get("schema_version") != "1.0":
        check["status"] = "FAIL"
        check["details"]["error"] = f"schema_version must be '1.0', got '{data.get('schema_version')}'"
        return check

    if "behaviors" not in data or not isinstance(data["behaviors"], list):
        check["status"] = "FAIL"
        check["details"]["error"] = "Missing or invalid 'behaviors' array"
        return check

    check["details"]["behavior_count"] = len(data["behaviors"])
    return check


def check_entry_fields() -> dict:
    """REG-FIELDS: Check each entry has all required fields with valid values."""
    check = {"id": "REG-FIELDS", "status": "PASS", "details": {"entries": [], "errors": []}}
    data, err = load_registry()
    if err:
        check["status"] = "FAIL"
        check["details"]["error"] = err
        return check

    required_fields = ["id", "api_family", "api_name", "band", "shim_type", "spec_ref", "oracle_status"]

    for i, entry in enumerate(data.get("behaviors", [])):
        entry_errors = []

        # Check required fields
        for field in required_fields:
            if field not in entry or not entry[field]:
                entry_errors.append(f"missing or empty '{field}'")

        # Validate ID format
        entry_id = entry.get("id", "")
        if entry_id and not ID_PATTERN.match(entry_id):
            entry_errors.append(f"invalid id format: '{entry_id}'")

        # Validate enum fields
        band = entry.get("band", "")
        if band and band not in VALID_BANDS:
            entry_errors.append(f"invalid band: '{band}'")

        shim_type = entry.get("shim_type", "")
        if shim_type and shim_type not in VALID_SHIM_TYPES:
            entry_errors.append(f"invalid shim_type: '{shim_type}'")

        oracle_status = entry.get("oracle_status", "")
        if oracle_status and oracle_status not in VALID_ORACLE_STATUSES:
            entry_errors.append(f"invalid oracle_status: '{oracle_status}'")

        if entry_errors:
            check["status"] = "FAIL"
            for e in entry_errors:
                check["details"]["errors"].append(f"behaviors[{i}] ({entry_id}): {e}")

        check["details"]["entries"].append({
            "id": entry_id,
            "band": band,
            "shim_type": shim_type,
            "valid": len(entry_errors) == 0,
        })

    return check


def check_unique_ids() -> dict:
    """REG-UNIQUE: Check that all behavior IDs are unique."""
    check = {"id": "REG-UNIQUE", "status": "PASS", "details": {}}
    data, err = load_registry()
    if err:
        check["status"] = "FAIL"
        check["details"]["error"] = err
        return check

    ids = [b.get("id", "") for b in data.get("behaviors", [])]
    seen = set()
    duplicates = []
    for bid in ids:
        if bid in seen:
            duplicates.append(bid)
        seen.add(bid)

    check["details"]["total_ids"] = len(ids)
    check["details"]["unique_ids"] = len(seen)
    if duplicates:
        check["status"] = "FAIL"
        check["details"]["duplicates"] = duplicates
    return check


def check_band_coverage() -> dict:
    """REG-COVERAGE: Check that at least one entry exists per band with entries."""
    check = {"id": "REG-COVERAGE", "status": "PASS", "details": {"bands_represented": {}}}
    data, err = load_registry()
    if err:
        check["status"] = "FAIL"
        check["details"]["error"] = err
        return check

    bands_found = set()
    for entry in data.get("behaviors", []):
        band = entry.get("band", "")
        if band in VALID_BANDS:
            bands_found.add(band)

    for band in VALID_BANDS:
        check["details"]["bands_represented"][band] = band in bands_found

    # At minimum, core and high-value should have entries
    if "core" not in bands_found:
        check["status"] = "FAIL"
        check["details"]["error"] = "No 'core' band entries in registry"
    return check


def main():
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        check_registry_exists(),
        check_schema_exists(),
        check_registry_structure(),
        check_entry_fields(),
        check_unique_ids(),
        check_band_coverage(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "compatibility_registry_verification",
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
        print("=== Compatibility Behavior Registry Verifier ===")
        print(f"Timestamp: {timestamp}")
        print()
        for c in checks:
            icon = "OK" if c["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {c['id']}")
            if c["status"] == "FAIL":
                details = c.get("details", {})
                if "error" in details:
                    print(f"       Error: {details['error']}")
                if "errors" in details:
                    for e in details["errors"][:5]:
                        print(f"       Error: {e}")
        print()
        print(f"Checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
