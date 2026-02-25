#!/usr/bin/env python3
"""bd-1cwp: Control-plane idempotency adoption verification gate.

Usage:
    python3 scripts/check_control_idempotency_adoption.py [--json] [--self-test]
"""

import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone
from pathlib import Path


# --- Constants ---

KEY_DERIVATION_SRC = ROOT / "crates" / "franken-node" / "src" / "remote" / "idempotency.rs"
DEDUP_STORE_SRC = ROOT / "crates" / "franken-node" / "src" / "remote" / "idempotency_store.rs"
ADOPTION_DOC = ROOT / "docs" / "integration" / "control_idempotency_adoption.md"
ADOPTION_REPORT = ROOT / "artifacts" / "10.15" / "control_idempotency_report.json"
SPEC_CONTRACT = ROOT / "docs" / "specs" / "section_10_15" / "bd-1cwp_contract.md"
TEST_FILE = ROOT / "tests" / "test_check_control_idempotency_adoption.py"

RETRYABLE_REQUESTS = [
    "health_probe",
    "rollout_notify",
    "migration_step",
    "sync_delta",
]

NON_RETRYABLE_REQUESTS = [
    "fencing_acquire",
]

CONNECTOR_DIR = ROOT / "crates" / "franken-node" / "src" / "connector"

# Patterns indicating custom idempotency logic
CUSTOM_IDEMPOTENCY_PATTERNS = [
    "fn derive_idempotency_key",
    "fn compute_idempotency",
    "idempotency_cache",
    "dedup_map",
]


def check_key_derivation_exists() -> dict:
    """CIA-KEY: Canonical key derivation source exists."""
    exists = KEY_DERIVATION_SRC.exists()
    return {
        "id": "CIA-KEY",
        "status": "PASS" if exists else "FAIL",
        "details": {"path": str(KEY_DERIVATION_SRC.relative_to(ROOT))},
    }


def check_dedup_store_exists() -> dict:
    """CIA-DEDUP: Canonical dedupe store source exists."""
    exists = DEDUP_STORE_SRC.exists()
    return {
        "id": "CIA-DEDUP",
        "status": "PASS" if exists else "FAIL",
        "details": {"path": str(DEDUP_STORE_SRC.relative_to(ROOT))},
    }


def check_adoption_doc_exists() -> dict:
    """CIA-DOC: Adoption document exists."""
    exists = ADOPTION_DOC.exists()
    return {
        "id": "CIA-DOC",
        "status": "PASS" if exists else "FAIL",
        "details": {"path": str(ADOPTION_DOC.relative_to(ROOT))},
    }


def check_adoption_report_exists() -> dict:
    """CIA-REPORT: Adoption report artifact exists and is valid."""
    if not ADOPTION_REPORT.exists():
        return {"id": "CIA-REPORT", "status": "FAIL", "details": {"error": "not found"}}
    try:
        data = json.loads(ADOPTION_REPORT.read_text())
        ok = (data.get("bead") == "bd-1cwp"
              and data.get("adoption_status") == "documented"
              and isinstance(data.get("retryable_requests"), list))
        return {"id": "CIA-REPORT", "status": "PASS" if ok else "FAIL", "details": {"valid": ok}}
    except json.JSONDecodeError as e:
        return {"id": "CIA-REPORT", "status": "FAIL", "details": {"error": str(e)}}


def check_retryable_requests_documented() -> dict:
    """CIA-RETRY: All retryable requests documented in adoption doc."""
    if not ADOPTION_DOC.exists():
        return {"id": "CIA-RETRY", "status": "FAIL", "details": {"error": "doc not found"}}
    content = ADOPTION_DOC.read_text()
    missing = [r for r in RETRYABLE_REQUESTS if r not in content]
    return {
        "id": "CIA-RETRY",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing": missing, "total": len(RETRYABLE_REQUESTS)},
    }


def check_non_retryable_documented() -> dict:
    """CIA-NORETRY: Non-retryable requests documented."""
    if not ADOPTION_DOC.exists():
        return {"id": "CIA-NORETRY", "status": "FAIL", "details": {"error": "doc not found"}}
    content = ADOPTION_DOC.read_text()
    missing = [r for r in NON_RETRYABLE_REQUESTS if r not in content]
    return {
        "id": "CIA-NORETRY",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing": missing},
    }


def check_derive_key_function() -> dict:
    """CIA-DERIVE: derive_key function exists in canonical source."""
    if not KEY_DERIVATION_SRC.exists():
        return {"id": "CIA-DERIVE", "status": "FAIL", "details": {"error": "source not found"}}
    content = KEY_DERIVATION_SRC.read_text()
    has_fn = "fn derive_key" in content
    return {"id": "CIA-DERIVE", "status": "PASS" if has_fn else "FAIL", "details": {"found": has_fn}}


def check_dedup_contract_documented() -> dict:
    """CIA-CONTRACT: Dedupe contract sections in adoption doc."""
    if not ADOPTION_DOC.exists():
        return {"id": "CIA-CONTRACT", "status": "FAIL", "details": {"error": "doc not found"}}
    content = ADOPTION_DOC.read_text()
    required = ["Dedupe Contract", "Epoch Binding", "Prohibition on Custom"]
    missing = [s for s in required if s not in content]
    return {
        "id": "CIA-CONTRACT",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing_sections": missing},
    }


def check_epoch_binding_documented() -> dict:
    """CIA-EPOCH: Epoch binding enforcement documented."""
    if not ADOPTION_DOC.exists():
        return {"id": "CIA-EPOCH", "status": "FAIL", "details": {"error": "doc not found"}}
    content = ADOPTION_DOC.read_text()
    has_epoch = "epoch-bound" in content.lower() or "epoch binding" in content.lower() or "Epoch Binding" in content
    return {"id": "CIA-EPOCH", "status": "PASS" if has_epoch else "FAIL", "details": {"found": has_epoch}}


def check_no_custom_idempotency() -> dict:
    """CIA-NOCUSTOM: No custom idempotency patterns in connector modules."""
    violations = []
    if CONNECTOR_DIR.exists():
        for rs_file in sorted(CONNECTOR_DIR.glob("*.rs")):
            content = rs_file.read_text()
            for pattern in CUSTOM_IDEMPOTENCY_PATTERNS:
                if pattern in content:
                    violations.append({
                        "file": str(rs_file.relative_to(ROOT)),
                        "pattern": pattern,
                    })
    return {
        "id": "CIA-NOCUSTOM",
        "status": "PASS" if not violations else "FAIL",
        "details": {"violations": violations},
    }


def check_report_retryable_count() -> dict:
    """CIA-COUNT: Report lists all 4 retryable requests."""
    if not ADOPTION_REPORT.exists():
        return {"id": "CIA-COUNT", "status": "FAIL", "details": {"error": "report not found"}}
    try:
        data = json.loads(ADOPTION_REPORT.read_text())
        retryable = data.get("retryable_requests", [])
        types = [r.get("request_type") for r in retryable]
        missing = [r for r in RETRYABLE_REQUESTS if r not in types]
        return {
            "id": "CIA-COUNT",
            "status": "PASS" if not missing else "FAIL",
            "details": {"count": len(retryable), "missing": missing},
        }
    except json.JSONDecodeError as e:
        return {"id": "CIA-COUNT", "status": "FAIL", "details": {"error": str(e)}}


def check_spec_contract_exists() -> dict:
    """CIA-SPEC: Spec contract exists."""
    exists = SPEC_CONTRACT.exists()
    return {"id": "CIA-SPEC", "status": "PASS" if exists else "FAIL",
            "details": {"path": str(SPEC_CONTRACT.relative_to(ROOT))}}


def check_test_file_exists() -> dict:
    """CIA-TESTS: Test file exists."""
    exists = TEST_FILE.exists()
    return {"id": "CIA-TESTS", "status": "PASS" if exists else "FAIL",
            "details": {"path": str(TEST_FILE.relative_to(ROOT))}}


def check_event_codes_documented() -> dict:
    """CIA-EVENTS: Event codes documented in adoption doc."""
    if not ADOPTION_DOC.exists():
        return {"id": "CIA-EVENTS", "status": "FAIL", "details": {"error": "doc not found"}}
    content = ADOPTION_DOC.read_text()
    codes = ["IDP-001", "IDP-002", "IDP-003", "IDP-004", "IDP-005"]
    missing = [c for c in codes if c not in content]
    return {
        "id": "CIA-EVENTS",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing": missing, "total": len(codes)},
    }


def check_invariants_documented() -> dict:
    """CIA-INV: Invariants documented in adoption doc."""
    if not ADOPTION_DOC.exists():
        return {"id": "CIA-INV", "status": "FAIL", "details": {"error": "doc not found"}}
    content = ADOPTION_DOC.read_text()
    invs = ["INV-IDP-CANONICAL-KEY", "INV-IDP-DEDUP-CONSULTED", "INV-IDP-EPOCH-BOUND",
            "INV-IDP-NO-CUSTOM", "INV-IDP-CONFLICT-HARD"]
    missing = [i for i in invs if i not in content]
    return {
        "id": "CIA-INV",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing": missing, "total": len(invs)},
    }


def self_test() -> dict:
    """Run all checks."""
    checks = [
        check_key_derivation_exists(),
        check_dedup_store_exists(),
        check_adoption_doc_exists(),
        check_adoption_report_exists(),
        check_retryable_requests_documented(),
        check_non_retryable_documented(),
        check_derive_key_function(),
        check_dedup_contract_documented(),
        check_epoch_binding_documented(),
        check_no_custom_idempotency(),
        check_report_retryable_count(),
        check_spec_contract_exists(),
        check_test_file_exists(),
        check_event_codes_documented(),
        check_invariants_documented(),
    ]

    failing = [c for c in checks if c["status"] != "PASS"]
    return {
        "gate": "control_idempotency_adoption_verification",
        "bead": "bd-1cwp",
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
    logger = configure_test_logging("check_control_idempotency_adoption")
    json_output = "--json" in sys.argv

    result = self_test()
    if json_output:
        print(json.dumps(result, indent=2))
    else:
        for c in result["checks"]:
            print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
        print(f"\nVerdict: {result['verdict']}")
    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
