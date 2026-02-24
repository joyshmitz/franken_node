#!/usr/bin/env python3
"""
Four-Doc Spec Pack Verifier.

Usage:
    python3 scripts/check_spec_pack.py [--json]
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
PACK_DIR = ROOT / "docs" / "compat_spec_pack"

REQUIRED_DOCS = [
    "PLAN_TO_PORT_NODE_BUN_SURFACES_TO_RUST.md",
    "EXISTING_NODE_BUN_STRUCTURE.md",
    "PROPOSED_ARCHITECTURE.md",
    "FEATURE_PARITY.md",
]


def check_docs_exist() -> dict:
    check = {"id": "PACK-EXISTS", "status": "PASS", "details": {"documents": {}}}
    for doc in REQUIRED_DOCS:
        path = PACK_DIR / doc
        exists = path.exists()
        check["details"]["documents"][doc] = exists
        if not exists:
            check["status"] = "FAIL"
    return check


def check_adr_references() -> dict:
    check = {"id": "PACK-ADR-REF", "status": "PASS", "details": {"references": {}}}
    for doc in REQUIRED_DOCS:
        path = PACK_DIR / doc
        if path.exists():
            text = path.read_text()
            has_ref = "ADR-001" in text or "hybrid baseline" in text.lower()
            check["details"]["references"][doc] = has_ref
            if not has_ref:
                check["status"] = "FAIL"
    return check


def check_not_blueprint_warning() -> dict:
    check = {"id": "PACK-NOT-BLUEPRINT", "status": "PASS", "details": {}}
    path = PACK_DIR / "EXISTING_NODE_BUN_STRUCTURE.md"
    if not path.exists():
        check["status"] = "FAIL"
        return check
    text = path.read_text().lower()
    has_warning = "not" in text and ("implementation blueprint" in text or "blueprint" in text)
    check["details"]["warning_present"] = has_warning
    if not has_warning:
        check["status"] = "FAIL"
    return check


def check_feature_parity_content() -> dict:
    check = {"id": "PACK-PARITY", "status": "PASS", "details": {}}
    path = PACK_DIR / "FEATURE_PARITY.md"
    if not path.exists():
        check["status"] = "FAIL"
        return check
    text = path.read_text().lower()
    has_family = "api family" in text or "by api" in text
    has_band = "band" in text
    has_status = "stub" in text or "native" in text
    check["details"]["has_family_tracking"] = has_family
    check["details"]["has_band_tracking"] = has_band
    check["details"]["has_status_tracking"] = has_status
    if not all([has_family, has_band, has_status]):
        check["status"] = "FAIL"
    return check


def check_release_gate() -> dict:
    check = {"id": "PACK-GATE", "status": "PASS", "details": {}}
    path = PACK_DIR / "PLAN_TO_PORT_NODE_BUN_SURFACES_TO_RUST.md"
    if not path.exists():
        check["status"] = "FAIL"
        return check
    text = path.read_text().lower()
    has_gate = "release" in text and "gate" in text
    check["details"]["release_gated"] = has_gate
    if not has_gate:
        check["status"] = "FAIL"
    return check


def main():
    logger = configure_test_logging("check_spec_pack")
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [check_docs_exist(), check_adr_references(), check_not_blueprint_warning(),
              check_feature_parity_content(), check_release_gate()]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "spec_pack_verification", "section": "10.2", "verdict": verdict,
        "timestamp": timestamp, "checks": checks,
        "summary": {"total_checks": len(checks), "passing_checks": len(checks) - len(failing), "failing_checks": len(failing)},
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Four-Doc Spec Pack Verifier ===")
        print(f"Timestamp: {timestamp}\n")
        for c in checks:
            print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
        print(f"\nChecks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass\nVerdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
