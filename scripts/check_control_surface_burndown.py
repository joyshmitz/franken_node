#!/usr/bin/env python3
"""
Control Surface Burn-Down Verification (bd-2h2s).

Validates that the asupersync control surface migration plan and burn-down CSV
are present, consistent, and contain no expired exceptions.

Usage:
    python3 scripts/check_control_surface_burndown.py [--json] [--self-test]
"""

import csv
import json
import sys
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

# --- Constants ---

BURNDOWN_CSV = ROOT / "artifacts" / "10.15" / "control_surface_burndown.csv"
MIGRATION_DOC = ROOT / "docs" / "migration" / "asupersync_control_surface_migration.md"
SPEC_CONTRACT = ROOT / "docs" / "specs" / "section_10_15" / "bd-2h2s_contract.md"
TEST_FILE = ROOT / "tests" / "test_check_control_surface_burndown.py"

REQUIRED_COLUMNS = [
    "module_path",
    "function_name",
    "invariant_violated",
    "target_bead",
    "migration_status",
    "closure_criteria",
    "exception_reason",
    "exception_expiry",
]

ALLOWED_STATUSES = {"not_started", "in_progress", "completed", "excepted"}

MIN_SURFACE_COUNT = 12


# --- Helpers ---

def _parse_csv(csv_path):
    """Parse CSV and return list of row dicts."""
    text = csv_path.read_text()
    reader = csv.DictReader(StringIO(text))
    return list(reader)


def _today_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# --- Check functions ---

def check_csv_exists() -> dict:
    """MIG-CSV-EXISTS: Burn-down CSV file exists."""
    exists = BURNDOWN_CSV.exists()
    return {
        "id": "MIG-CSV-EXISTS",
        "status": "PASS" if exists else "FAIL",
        "details": {"path": str(BURNDOWN_CSV.relative_to(ROOT))},
        "event": "MIG-001" if exists else "ERR_CSV_NOT_FOUND",
    }


def check_migration_doc_exists() -> dict:
    """MIG-DOC-EXISTS: Migration plan document exists."""
    exists = MIGRATION_DOC.exists()
    return {
        "id": "MIG-DOC-EXISTS",
        "status": "PASS" if exists else "FAIL",
        "details": {"path": str(MIGRATION_DOC.relative_to(ROOT))},
        "event": "MIG-001" if exists else "ERR_MIGRATION_DOC_NOT_FOUND",
    }


def check_spec_contract_exists() -> dict:
    """MIG-SPEC-EXISTS: Spec contract exists."""
    exists = SPEC_CONTRACT.exists()
    return {
        "id": "MIG-SPEC-EXISTS",
        "status": "PASS" if exists else "FAIL",
        "details": {"path": str(SPEC_CONTRACT.relative_to(ROOT))},
    }


def check_test_file_exists() -> dict:
    """MIG-TESTS-EXISTS: Test file exists."""
    exists = TEST_FILE.exists()
    return {
        "id": "MIG-TESTS-EXISTS",
        "status": "PASS" if exists else "FAIL",
        "details": {"path": str(TEST_FILE.relative_to(ROOT))},
    }


def check_csv_required_columns() -> dict:
    """MIG-CSV-COLUMNS: All required columns present in CSV."""
    if not BURNDOWN_CSV.exists():
        return {
            "id": "MIG-CSV-COLUMNS",
            "status": "FAIL",
            "details": {"error": "CSV not found"},
        }
    text = BURNDOWN_CSV.read_text()
    reader = csv.DictReader(StringIO(text))
    fieldnames = reader.fieldnames or []
    missing = [c for c in REQUIRED_COLUMNS if c not in fieldnames]
    return {
        "id": "MIG-CSV-COLUMNS",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_columns": missing, "found_columns": list(fieldnames)},
    }


def check_csv_min_surfaces() -> dict:
    """MIG-CSV-MIN: CSV contains at least MIN_SURFACE_COUNT entries."""
    if not BURNDOWN_CSV.exists():
        return {
            "id": "MIG-CSV-MIN",
            "status": "FAIL",
            "details": {"error": "CSV not found"},
        }
    rows = _parse_csv(BURNDOWN_CSV)
    count = len(rows)
    return {
        "id": "MIG-CSV-MIN",
        "status": "PASS" if count >= MIN_SURFACE_COUNT else "FAIL",
        "details": {"total_surfaces": count, "minimum_required": MIN_SURFACE_COUNT},
    }


def check_csv_status_values() -> dict:
    """MIG-CSV-STATUS: All migration_status values are in allowed set."""
    if not BURNDOWN_CSV.exists():
        return {
            "id": "MIG-CSV-STATUS",
            "status": "FAIL",
            "details": {"error": "CSV not found"},
        }
    rows = _parse_csv(BURNDOWN_CSV)
    invalid = []
    for i, row in enumerate(rows):
        status = row.get("migration_status", "").strip()
        if status not in ALLOWED_STATUSES:
            invalid.append({"row": i + 2, "status": status})
    return {
        "id": "MIG-CSV-STATUS",
        "status": "PASS" if not invalid else "FAIL",
        "details": {"invalid_statuses": invalid},
    }


def check_csv_status_distribution() -> dict:
    """MIG-CSV-DIST: Compute status distribution from CSV."""
    if not BURNDOWN_CSV.exists():
        return {
            "id": "MIG-CSV-DIST",
            "status": "FAIL",
            "details": {"error": "CSV not found"},
        }
    rows = _parse_csv(BURNDOWN_CSV)
    dist = {"completed": 0, "in_progress": 0, "not_started": 0, "excepted": 0}
    for row in rows:
        status = row.get("migration_status", "").strip()
        if status in dist:
            dist[status] += 1
    return {
        "id": "MIG-CSV-DIST",
        "status": "PASS",
        "details": {
            "total_surfaces": len(rows),
            "completed": dist["completed"],
            "in_progress": dist["in_progress"],
            "not_started": dist["not_started"],
            "excepted": dist["excepted"],
        },
        "event": "MIG-002",
    }


def check_no_expired_exceptions() -> dict:
    """MIG-NO-EXPIRED: No excepted surface has an expired exception_expiry."""
    if not BURNDOWN_CSV.exists():
        return {
            "id": "MIG-NO-EXPIRED",
            "status": "FAIL",
            "details": {"error": "CSV not found"},
        }
    rows = _parse_csv(BURNDOWN_CSV)
    today = _today_str()
    expired = []
    for i, row in enumerate(rows):
        status = row.get("migration_status", "").strip()
        expiry = row.get("exception_expiry", "").strip()
        if status == "excepted" and expiry:
            if expiry < today:
                expired.append({
                    "row": i + 2,
                    "module_path": row.get("module_path", ""),
                    "function_name": row.get("function_name", ""),
                    "exception_expiry": expiry,
                })
    ok = len(expired) == 0
    return {
        "id": "MIG-NO-EXPIRED",
        "status": "PASS" if ok else "FAIL",
        "details": {"expired_exceptions": expired},
        "event": "MIG-003" if ok else "MIG-004",
    }


def check_exception_has_reason() -> dict:
    """MIG-EXC-REASON: Every excepted surface has a non-empty exception_reason."""
    if not BURNDOWN_CSV.exists():
        return {
            "id": "MIG-EXC-REASON",
            "status": "FAIL",
            "details": {"error": "CSV not found"},
        }
    rows = _parse_csv(BURNDOWN_CSV)
    missing_reason = []
    for i, row in enumerate(rows):
        status = row.get("migration_status", "").strip()
        reason = row.get("exception_reason", "").strip()
        if status == "excepted" and not reason:
            missing_reason.append({
                "row": i + 2,
                "module_path": row.get("module_path", ""),
                "function_name": row.get("function_name", ""),
            })
    return {
        "id": "MIG-EXC-REASON",
        "status": "PASS" if not missing_reason else "FAIL",
        "details": {"missing_reasons": missing_reason},
    }


def check_exception_has_expiry() -> dict:
    """MIG-EXC-EXPIRY: Every excepted surface has a non-empty exception_expiry."""
    if not BURNDOWN_CSV.exists():
        return {
            "id": "MIG-EXC-EXPIRY",
            "status": "FAIL",
            "details": {"error": "CSV not found"},
        }
    rows = _parse_csv(BURNDOWN_CSV)
    missing_expiry = []
    for i, row in enumerate(rows):
        status = row.get("migration_status", "").strip()
        expiry = row.get("exception_expiry", "").strip()
        if status == "excepted" and not expiry:
            missing_expiry.append({
                "row": i + 2,
                "module_path": row.get("module_path", ""),
                "function_name": row.get("function_name", ""),
            })
    return {
        "id": "MIG-EXC-EXPIRY",
        "status": "PASS" if not missing_expiry else "FAIL",
        "details": {"missing_expiries": missing_expiry},
    }


def check_migration_doc_sections() -> dict:
    """MIG-DOC-SECTIONS: Migration doc contains required sections."""
    if not MIGRATION_DOC.exists():
        return {
            "id": "MIG-DOC-SECTIONS",
            "status": "FAIL",
            "details": {"error": "migration doc not found"},
        }
    content = MIGRATION_DOC.read_text()
    required_sections = [
        "Inventory",
        "Exception Surfaces",
        "Burn-Down Schedule",
        "Invariants",
        "Event Codes",
    ]
    missing = [s for s in required_sections if s not in content]
    return {
        "id": "MIG-DOC-SECTIONS",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_sections": missing},
    }


def check_closure_criteria_nonempty() -> dict:
    """MIG-CLOSURE: Every surface has a non-empty closure_criteria."""
    if not BURNDOWN_CSV.exists():
        return {
            "id": "MIG-CLOSURE",
            "status": "FAIL",
            "details": {"error": "CSV not found"},
        }
    rows = _parse_csv(BURNDOWN_CSV)
    empty_criteria = []
    for i, row in enumerate(rows):
        criteria = row.get("closure_criteria", "").strip()
        if not criteria:
            empty_criteria.append({
                "row": i + 2,
                "module_path": row.get("module_path", ""),
                "function_name": row.get("function_name", ""),
            })
    return {
        "id": "MIG-CLOSURE",
        "status": "PASS" if not empty_criteria else "FAIL",
        "details": {"empty_criteria": empty_criteria},
    }


# --- Self test ---

def self_test() -> dict:
    """Run all checks and return structured result."""
    checks = [
        check_csv_exists(),
        check_migration_doc_exists(),
        check_spec_contract_exists(),
        check_test_file_exists(),
        check_csv_required_columns(),
        check_csv_min_surfaces(),
        check_csv_status_values(),
        check_csv_status_distribution(),
        check_no_expired_exceptions(),
        check_exception_has_reason(),
        check_exception_has_expiry(),
        check_migration_doc_sections(),
        check_closure_criteria_nonempty(),
    ]

    failing = [c for c in checks if c["status"] != "PASS"]
    events = [c.get("event") for c in checks if c.get("event")]
    events.append("MIG-005")

    return {
        "gate": "control_surface_burndown_verification",
        "bead": "bd-2h2s",
        "section": "10.15",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "events": events,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": len(checks) - len(failing),
            "failing_checks": len(failing),
        },
    }


def main():
    logger = configure_test_logging("check_control_surface_burndown")
    json_output = "--json" in sys.argv
    run_self_test = "--self-test" in sys.argv

    result = self_test()

    if json_output:
        print(json.dumps(result, indent=2))
    else:
        for c in result["checks"]:
            print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
        print(f"\nVerdict: {result['verdict']}")

    if run_self_test:
        sys.exit(0 if result["verdict"] == "PASS" else 1)
    else:
        sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
