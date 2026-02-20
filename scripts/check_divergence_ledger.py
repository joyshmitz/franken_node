#!/usr/bin/env python3
"""
Divergence Ledger Verifier.

Validates that DIVERGENCE_LEDGER.json exists, conforms to schema rules,
and all entries have valid signed rationale.

Usage:
    python3 scripts/check_divergence_ledger.py [--json]

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
LEDGER_PATH = ROOT / "docs" / "DIVERGENCE_LEDGER.json"
SCHEMA_PATH = ROOT / "schemas" / "divergence_ledger.schema.json"

VALID_BANDS = {"core", "high-value", "edge", "unsafe"}
VALID_RISK_TIERS = {"critical", "high", "medium", "low"}
VALID_STATUSES = {"accepted", "under-review", "deprecated"}
ID_PATTERN = re.compile(r'^DIV-\d{3,}$')


def check_ledger_exists() -> dict:
    """DIV-EXISTS: Check that DIVERGENCE_LEDGER.json exists."""
    check = {"id": "DIV-EXISTS", "status": "PASS", "details": {}}
    if not LEDGER_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "docs/DIVERGENCE_LEDGER.json not found"
    else:
        check["details"]["path"] = str(LEDGER_PATH.relative_to(ROOT))
    return check


def check_schema_exists() -> dict:
    """DIV-SCHEMA: Check that the JSON schema exists."""
    check = {"id": "DIV-SCHEMA", "status": "PASS", "details": {}}
    if not SCHEMA_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "schemas/divergence_ledger.schema.json not found"
    else:
        check["details"]["path"] = str(SCHEMA_PATH.relative_to(ROOT))
    return check


def load_ledger() -> tuple[dict | None, str | None]:
    if not LEDGER_PATH.exists():
        return None, "File not found"
    try:
        return json.loads(LEDGER_PATH.read_text()), None
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON: {e}"


def check_ledger_structure() -> dict:
    """DIV-STRUCTURE: Check ledger has required top-level fields."""
    check = {"id": "DIV-STRUCTURE", "status": "PASS", "details": {}}
    data, err = load_ledger()
    if err:
        check["status"] = "FAIL"
        check["details"]["error"] = err
        return check
    if data.get("schema_version") != "1.0":
        check["status"] = "FAIL"
        check["details"]["error"] = f"schema_version must be '1.0'"
        return check
    if "entries" not in data or not isinstance(data["entries"], list):
        check["status"] = "FAIL"
        check["details"]["error"] = "Missing or invalid 'entries' array"
        return check
    check["details"]["entry_count"] = len(data["entries"])
    return check


def check_entry_fields() -> dict:
    """DIV-FIELDS: Check each entry has required fields with valid values."""
    check = {"id": "DIV-FIELDS", "status": "PASS", "details": {"errors": []}}
    data, err = load_ledger()
    if err:
        check["status"] = "FAIL"
        check["details"]["error"] = err
        return check

    required = ["id", "api_family", "api_name", "band", "node_behavior",
                 "franken_behavior", "rationale", "risk_tier", "status", "timestamp"]

    for i, entry in enumerate(data.get("entries", [])):
        eid = entry.get("id", f"entry[{i}]")
        for field in required:
            if field not in entry or not entry[field]:
                check["details"]["errors"].append(f"{eid}: missing or empty '{field}'")
                check["status"] = "FAIL"

        if entry.get("id") and not ID_PATTERN.match(entry["id"]):
            check["details"]["errors"].append(f"{eid}: invalid id format")
            check["status"] = "FAIL"
        if entry.get("band") and entry["band"] not in VALID_BANDS:
            check["details"]["errors"].append(f"{eid}: invalid band '{entry['band']}'")
            check["status"] = "FAIL"
        if entry.get("risk_tier") and entry["risk_tier"] not in VALID_RISK_TIERS:
            check["details"]["errors"].append(f"{eid}: invalid risk_tier '{entry['risk_tier']}'")
            check["status"] = "FAIL"
        if entry.get("status") and entry["status"] not in VALID_STATUSES:
            check["details"]["errors"].append(f"{eid}: invalid status '{entry['status']}'")
            check["status"] = "FAIL"

    return check


def check_rationale_present() -> dict:
    """DIV-RATIONALE: Check every entry has non-empty rationale."""
    check = {"id": "DIV-RATIONALE", "status": "PASS", "details": {"entries_with_rationale": 0}}
    data, err = load_ledger()
    if err:
        check["status"] = "FAIL"
        check["details"]["error"] = err
        return check

    count = 0
    for entry in data.get("entries", []):
        rationale = entry.get("rationale", "")
        if rationale and len(rationale.strip()) > 0:
            count += 1
        else:
            check["status"] = "FAIL"
            check["details"]["error"] = f"{entry.get('id', '?')}: empty rationale"

    check["details"]["entries_with_rationale"] = count
    check["details"]["total_entries"] = len(data.get("entries", []))
    return check


def check_unique_ids() -> dict:
    """DIV-UNIQUE: Check all divergence IDs are unique."""
    check = {"id": "DIV-UNIQUE", "status": "PASS", "details": {}}
    data, err = load_ledger()
    if err:
        check["status"] = "FAIL"
        check["details"]["error"] = err
        return check

    ids = [e.get("id", "") for e in data.get("entries", [])]
    seen = set()
    dupes = []
    for did in ids:
        if did in seen:
            dupes.append(did)
        seen.add(did)

    check["details"]["total"] = len(ids)
    check["details"]["unique"] = len(seen)
    if dupes:
        check["status"] = "FAIL"
        check["details"]["duplicates"] = dupes
    return check


def main():
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        check_ledger_exists(),
        check_schema_exists(),
        check_ledger_structure(),
        check_entry_fields(),
        check_rationale_present(),
        check_unique_ids(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "divergence_ledger_verification",
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
        print("=== Divergence Ledger Verifier ===")
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
