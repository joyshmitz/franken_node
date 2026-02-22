#!/usr/bin/env python3
"""bd-1hbw: Epoch barrier adoption verification gate.

Usage:
    python3 scripts/check_epoch_barrier_adoption.py [--json] [--self-test]
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BARRIER_SRC = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "epoch_transition_barrier.rs"
BARRIER_MOD = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "mod.rs"
ADOPTION_DOC = ROOT / "docs" / "integration" / "control_epoch_barrier_adoption.md"
TRANSCRIPT = ROOT / "artifacts" / "10.15" / "control_epoch_barrier_transcript.json"
SPEC_CONTRACT = ROOT / "docs" / "specs" / "section_10_15" / "bd-1hbw_contract.md"
TEST_FILE = ROOT / "tests" / "test_check_epoch_barrier_adoption.py"

PARTICIPANTS = [
    "connector_lifecycle",
    "rollout_engine",
    "fencing_service",
    "health_gate",
]


def check_barrier_source_exists() -> dict:
    exists = BARRIER_SRC.exists()
    return {"id": "EBA-SRC", "status": "PASS" if exists else "FAIL",
            "details": {"path": str(BARRIER_SRC.relative_to(ROOT))}}


def check_barrier_mod_wired() -> dict:
    if not BARRIER_MOD.exists():
        return {"id": "EBA-MOD", "status": "FAIL", "details": {"error": "mod.rs not found"}}
    content = BARRIER_MOD.read_text()
    ok = "pub mod epoch_transition_barrier;" in content
    return {"id": "EBA-MOD", "status": "PASS" if ok else "FAIL", "details": {"wired": ok}}


def check_adoption_doc_exists() -> dict:
    exists = ADOPTION_DOC.exists()
    return {"id": "EBA-DOC", "status": "PASS" if exists else "FAIL",
            "details": {"path": str(ADOPTION_DOC.relative_to(ROOT))}}


def check_transcript_exists() -> dict:
    if not TRANSCRIPT.exists():
        return {"id": "EBA-TRANSCRIPT", "status": "FAIL", "details": {"error": "not found"}}
    try:
        data = json.loads(TRANSCRIPT.read_text())
        ok = (data.get("bead") == "bd-1hbw"
              and data.get("adoption_status") == "documented"
              and isinstance(data.get("barrier_participants"), list))
        return {"id": "EBA-TRANSCRIPT", "status": "PASS" if ok else "FAIL", "details": {"valid": ok}}
    except json.JSONDecodeError as e:
        return {"id": "EBA-TRANSCRIPT", "status": "FAIL", "details": {"error": str(e)}}


def check_participants_documented() -> dict:
    if not ADOPTION_DOC.exists():
        return {"id": "EBA-PARTICIPANTS", "status": "FAIL", "details": {"error": "doc not found"}}
    content = ADOPTION_DOC.read_text()
    missing = [p for p in PARTICIPANTS if p not in content]
    return {
        "id": "EBA-PARTICIPANTS",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing": missing, "total": len(PARTICIPANTS)},
    }


def check_abort_semantics_documented() -> dict:
    if not ADOPTION_DOC.exists():
        return {"id": "EBA-ABORT", "status": "FAIL", "details": {"error": "doc not found"}}
    content = ADOPTION_DOC.read_text()
    required = ["Abort Semantics", "Timeout abort", "Cancel abort", "No split-brain"]
    missing = [s for s in required if s.lower() not in content.lower()]
    return {
        "id": "EBA-ABORT",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing": missing},
    }


def check_event_codes_documented() -> dict:
    if not ADOPTION_DOC.exists():
        return {"id": "EBA-EVENTS", "status": "FAIL", "details": {"error": "doc not found"}}
    content = ADOPTION_DOC.read_text()
    codes = ["EPB-001", "EPB-002", "EPB-003", "EPB-004", "EPB-005", "EPB-006"]
    missing = [c for c in codes if c not in content]
    return {
        "id": "EBA-EVENTS",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing": missing, "total": len(codes)},
    }


def check_invariants_documented() -> dict:
    if not ADOPTION_DOC.exists():
        return {"id": "EBA-INV", "status": "FAIL", "details": {"error": "doc not found"}}
    content = ADOPTION_DOC.read_text()
    invs = ["INV-EPB-CANONICAL", "INV-EPB-ALL-ARRIVE", "INV-EPB-NO-SPLIT-BRAIN",
            "INV-EPB-DETERMINISTIC-ABORT", "INV-EPB-TRANSCRIPT-STABLE"]
    missing = [i for i in invs if i not in content]
    return {
        "id": "EBA-INV",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing": missing, "total": len(invs)},
    }


def check_transcript_participants_count() -> dict:
    if not TRANSCRIPT.exists():
        return {"id": "EBA-PCOUNT", "status": "FAIL", "details": {"error": "not found"}}
    try:
        data = json.loads(TRANSCRIPT.read_text())
        participants = data.get("barrier_participants", [])
        ids = [p.get("participant_id") for p in participants]
        missing = [p for p in PARTICIPANTS if p not in ids]
        return {
            "id": "EBA-PCOUNT",
            "status": "PASS" if not missing else "FAIL",
            "details": {"count": len(participants), "missing": missing},
        }
    except json.JSONDecodeError as e:
        return {"id": "EBA-PCOUNT", "status": "FAIL", "details": {"error": str(e)}}


def check_transcript_test_scenarios() -> dict:
    if not TRANSCRIPT.exists():
        return {"id": "EBA-SCENARIOS", "status": "FAIL", "details": {"error": "not found"}}
    try:
        data = json.loads(TRANSCRIPT.read_text())
        scenarios = data.get("test_scenarios", {})
        required = ["full_commit", "timeout_abort", "cancel_abort"]
        missing = [s for s in required if s not in scenarios]
        return {
            "id": "EBA-SCENARIOS",
            "status": "PASS" if not missing else "FAIL",
            "details": {"missing": missing, "total": len(required)},
        }
    except json.JSONDecodeError as e:
        return {"id": "EBA-SCENARIOS", "status": "FAIL", "details": {"error": str(e)}}


def check_spec_contract_exists() -> dict:
    exists = SPEC_CONTRACT.exists()
    return {"id": "EBA-SPEC", "status": "PASS" if exists else "FAIL",
            "details": {"path": str(SPEC_CONTRACT.relative_to(ROOT))}}


def check_test_file_exists() -> dict:
    exists = TEST_FILE.exists()
    return {"id": "EBA-TESTS", "status": "PASS" if exists else "FAIL",
            "details": {"path": str(TEST_FILE.relative_to(ROOT))}}


def check_no_custom_barrier() -> dict:
    """No custom barrier protocol in connector modules."""
    connector_dir = ROOT / "crates" / "franken-node" / "src" / "connector"
    violations = []
    patterns = ["BarrierProtocol", "fn propose_barrier", "fn barrier_commit"]
    if connector_dir.exists():
        for rs_file in sorted(connector_dir.glob("*.rs")):
            content = rs_file.read_text()
            for pattern in patterns:
                if pattern in content:
                    violations.append({
                        "file": str(rs_file.relative_to(ROOT)),
                        "pattern": pattern,
                    })
    return {
        "id": "EBA-NOCUSTOM",
        "status": "PASS" if not violations else "FAIL",
        "details": {"violations": violations},
    }


def self_test() -> dict:
    checks = [
        check_barrier_source_exists(),
        check_barrier_mod_wired(),
        check_adoption_doc_exists(),
        check_transcript_exists(),
        check_participants_documented(),
        check_abort_semantics_documented(),
        check_event_codes_documented(),
        check_invariants_documented(),
        check_transcript_participants_count(),
        check_transcript_test_scenarios(),
        check_spec_contract_exists(),
        check_test_file_exists(),
        check_no_custom_barrier(),
    ]

    failing = [c for c in checks if c["status"] != "PASS"]
    return {
        "gate": "epoch_barrier_adoption_verification",
        "bead": "bd-1hbw",
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
            print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
        print(f"\nVerdict: {result['verdict']}")
    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
