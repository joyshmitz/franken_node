#!/usr/bin/env python3
"""bd-3tpg: Control-plane cancellation injection adoption verification gate.

Verifies that the canonical all-point cancellation injection framework (bd-876n)
is properly adopted across all 6 critical control-plane workflows.

Usage:
    python3 scripts/check_control_cancel_injection.py [--json] [--self-test]
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# --- Constants ---

ADOPTION_DOC = ROOT / "docs" / "testing" / "control_cancellation_injection.md"
ADOPTION_REPORT = ROOT / "artifacts" / "10.15" / "control_cancel_injection_report.json"
SPEC_CONTRACT = ROOT / "docs" / "specs" / "section_10_15" / "bd-3tpg_contract.md"
TEST_FILE = ROOT / "tests" / "test_check_control_cancel_injection.py"
CANCEL_INJECTION_SRC = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "cancellation_injection.rs"
EVIDENCE_FILE = ROOT / "artifacts" / "section_10_15" / "bd-3tpg" / "verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts" / "section_10_15" / "bd-3tpg" / "verification_summary.md"

REQUIRED_WORKFLOWS = [
    "connector_lifecycle",
    "rollout_transition",
    "quarantine_promotion",
    "migration_orchestration",
    "fencing_acquire",
    "health_gate_evaluation",
]

REQUIRED_EVENT_CODES = ["CIJ-001", "CIJ-002", "CIJ-003", "CIJ-004", "CIJ-005"]

REQUIRED_INVARIANTS = [
    "INV-CIG-CANONICAL-ONLY",
    "INV-CIG-ALL-WORKFLOWS",
    "INV-CIG-FULL-MATRIX",
    "INV-CIG-ZERO-FAILURES",
    "INV-CIG-LEAK-FREE",
    "INV-CIG-HALFCOMMIT-FREE",
    "INV-CIG-QUIESCENCE-SAFE",
    "INV-CIG-REPORT-COMPLETE",
]

REQUIRED_DOC_SECTIONS = [
    "All-Point Injection Model",
    "Critical Workflows",
    "Per-Workflow Invariant Assertions",
    "No Obligation Leaks",
    "No Half-Commits",
    "No Quiescence Violations",
    "Prohibition on Custom Injection Logic",
]

MIN_INJECTION_POINTS = 30


def check_adoption_doc_exists() -> dict:
    """CCI-001: Adoption document exists."""
    exists = ADOPTION_DOC.exists()
    return {
        "id": "CCI-001",
        "status": "PASS" if exists else "FAIL",
        "details": {"path": str(ADOPTION_DOC.relative_to(ROOT))},
    }


def check_adoption_doc_sections() -> dict:
    """CCI-002: Adoption document contains required sections."""
    if not ADOPTION_DOC.exists():
        return {"id": "CCI-002", "status": "FAIL", "details": {"error": "doc not found"}}
    content = ADOPTION_DOC.read_text()
    missing = [s for s in REQUIRED_DOC_SECTIONS if s not in content]
    return {
        "id": "CCI-002",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_sections": missing, "total": len(REQUIRED_DOC_SECTIONS)},
    }


def check_workflows_documented() -> dict:
    """CCI-003: All 6 critical workflows documented in adoption doc."""
    if not ADOPTION_DOC.exists():
        return {"id": "CCI-003", "status": "FAIL", "details": {"error": "doc not found"}}
    content = ADOPTION_DOC.read_text()
    missing = [w for w in REQUIRED_WORKFLOWS if w not in content]
    return {
        "id": "CCI-003",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing": missing, "total": len(REQUIRED_WORKFLOWS)},
    }


def check_report_exists() -> dict:
    """CCI-004: Adoption report exists and is valid JSON with required fields."""
    if not ADOPTION_REPORT.exists():
        return {"id": "CCI-004", "status": "FAIL", "details": {"error": "not found"}}
    try:
        data = json.loads(ADOPTION_REPORT.read_text())
        ok = (
            data.get("bead") == "bd-3tpg"
            and data.get("section") == "10.15"
            and data.get("adoption_status") == "documented"
        )
        return {
            "id": "CCI-004",
            "status": "PASS" if ok else "FAIL",
            "details": {"valid": ok, "bead": data.get("bead"), "section": data.get("section")},
        }
    except json.JSONDecodeError as e:
        return {"id": "CCI-004", "status": "FAIL", "details": {"error": str(e)}}


def check_report_workflows() -> dict:
    """CCI-005: Report lists all 6 workflows with all_pass=true."""
    if not ADOPTION_REPORT.exists():
        return {"id": "CCI-005", "status": "FAIL", "details": {"error": "report not found"}}
    try:
        data = json.loads(ADOPTION_REPORT.read_text())
        workflows = data.get("workflows", [])
        names = [w.get("name") for w in workflows]
        missing = [w for w in REQUIRED_WORKFLOWS if w not in names]
        all_pass = all(w.get("all_pass") is True for w in workflows)
        ok = not missing and all_pass
        return {
            "id": "CCI-005",
            "status": "PASS" if ok else "FAIL",
            "details": {
                "workflow_count": len(workflows),
                "missing": missing,
                "all_pass": all_pass,
            },
        }
    except json.JSONDecodeError as e:
        return {"id": "CCI-005", "status": "FAIL", "details": {"error": str(e)}}


def check_report_injection_points() -> dict:
    """CCI-006: Report summary has total_injection_points >= 30, total_failures = 0."""
    if not ADOPTION_REPORT.exists():
        return {"id": "CCI-006", "status": "FAIL", "details": {"error": "report not found"}}
    try:
        data = json.loads(ADOPTION_REPORT.read_text())
        summary = data.get("summary", {})
        total_points = summary.get("total_injection_points", 0)
        total_failures = summary.get("total_failures", -1)
        ok = total_points >= MIN_INJECTION_POINTS and total_failures == 0
        return {
            "id": "CCI-006",
            "status": "PASS" if ok else "FAIL",
            "details": {
                "total_injection_points": total_points,
                "total_failures": total_failures,
                "min_required": MIN_INJECTION_POINTS,
            },
        }
    except json.JSONDecodeError as e:
        return {"id": "CCI-006", "status": "FAIL", "details": {"error": str(e)}}


def check_cancellation_injection_source() -> dict:
    """CCI-007: Upstream cancellation_injection.rs source exists."""
    exists = CANCEL_INJECTION_SRC.exists()
    return {
        "id": "CCI-007",
        "status": "PASS" if exists else "FAIL",
        "details": {"path": str(CANCEL_INJECTION_SRC.relative_to(ROOT))},
    }


def check_cancellation_injection_framework() -> dict:
    """CCI-008: Upstream source contains CancellationInjectionFramework struct."""
    if not CANCEL_INJECTION_SRC.exists():
        return {"id": "CCI-008", "status": "FAIL", "details": {"error": "source not found"}}
    content = CANCEL_INJECTION_SRC.read_text()
    has_framework = "CancellationInjectionFramework" in content
    has_matrix = "CancelInjectionMatrix" in content
    ok = has_framework and has_matrix
    return {
        "id": "CCI-008",
        "status": "PASS" if ok else "FAIL",
        "details": {"has_framework": has_framework, "has_matrix": has_matrix},
    }


def check_event_codes_documented() -> dict:
    """CCI-009: Event codes CIJ-001 through CIJ-005 documented in adoption doc."""
    if not ADOPTION_DOC.exists():
        return {"id": "CCI-009", "status": "FAIL", "details": {"error": "doc not found"}}
    content = ADOPTION_DOC.read_text()
    missing = [c for c in REQUIRED_EVENT_CODES if c not in content]
    return {
        "id": "CCI-009",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing": missing, "total": len(REQUIRED_EVENT_CODES)},
    }


def check_invariants_documented() -> dict:
    """CCI-010: Invariants documented in adoption doc."""
    if not ADOPTION_DOC.exists():
        return {"id": "CCI-010", "status": "FAIL", "details": {"error": "doc not found"}}
    content = ADOPTION_DOC.read_text()
    missing = [inv for inv in REQUIRED_INVARIANTS if inv not in content]
    return {
        "id": "CCI-010",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing": missing, "total": len(REQUIRED_INVARIANTS)},
    }


def check_spec_contract_exists() -> dict:
    """CCI-011: Spec contract exists."""
    exists = SPEC_CONTRACT.exists()
    return {
        "id": "CCI-011",
        "status": "PASS" if exists else "FAIL",
        "details": {"path": str(SPEC_CONTRACT.relative_to(ROOT))},
    }


def check_test_file_exists() -> dict:
    """CCI-012: Test file exists."""
    exists = TEST_FILE.exists()
    return {
        "id": "CCI-012",
        "status": "PASS" if exists else "FAIL",
        "details": {"path": str(TEST_FILE.relative_to(ROOT))},
    }


def check_evidence_file_exists() -> dict:
    """CCI-013: Verification evidence file exists."""
    exists = EVIDENCE_FILE.exists()
    return {
        "id": "CCI-013",
        "status": "PASS" if exists else "FAIL",
        "details": {"path": str(EVIDENCE_FILE.relative_to(ROOT))},
    }


def check_summary_file_exists() -> dict:
    """CCI-014: Verification summary file exists."""
    exists = SUMMARY_FILE.exists()
    return {
        "id": "CCI-014",
        "status": "PASS" if exists else "FAIL",
        "details": {"path": str(SUMMARY_FILE.relative_to(ROOT))},
    }


def check_no_custom_injection_logic() -> dict:
    """CCI-015: No custom cancellation injection patterns in connector modules."""
    connector_dir = ROOT / "crates" / "franken-node" / "src" / "connector"
    # Patterns that would indicate custom injection logic (prohibited by INV-CIG-CANONICAL-ONLY)
    custom_patterns = [
        "fn inject_cancel",
        "fn custom_cancel",
        "cancel_injection_custom",
        "fn manual_cancel_test",
    ]
    violations = []
    if connector_dir.exists():
        for rs_file in sorted(connector_dir.glob("*.rs")):
            content = rs_file.read_text()
            for pattern in custom_patterns:
                if pattern in content:
                    violations.append({
                        "file": str(rs_file.relative_to(ROOT)),
                        "pattern": pattern,
                    })
    return {
        "id": "CCI-015",
        "status": "PASS" if not violations else "FAIL",
        "details": {"violations": violations},
    }


def self_test() -> dict:
    """Run all checks and return full result dict."""
    checks = [
        check_adoption_doc_exists(),
        check_adoption_doc_sections(),
        check_workflows_documented(),
        check_report_exists(),
        check_report_workflows(),
        check_report_injection_points(),
        check_cancellation_injection_source(),
        check_cancellation_injection_framework(),
        check_event_codes_documented(),
        check_invariants_documented(),
        check_spec_contract_exists(),
        check_test_file_exists(),
        check_evidence_file_exists(),
        check_summary_file_exists(),
        check_no_custom_injection_logic(),
    ]

    failing = [c for c in checks if c["status"] != "PASS"]
    return {
        "gate": "control_cancel_injection_verification",
        "bead": "bd-3tpg",
        "section": "10.15",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": len(checks) - len(failing),
            "failing_checks": len(failing),
        },
    }


def main():
    json_output = "--json" in sys.argv

    result = self_test()
    if json_output:
        print(json.dumps(result, indent=2))
    else:
        for c in result["checks"]:
            print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}: {c.get('details', {})}")
        print(f"\nVerdict: {result['verdict']} ({result['summary']['passing_checks']}/{result['summary']['total_checks']})")
    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
