#!/usr/bin/env python3
"""Verification script for bd-1vm quarantine/recall workflow."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

SPEC_PATH = ROOT / "docs/specs/section_10_4/bd-1vm_contract.md"
RUST_IMPL_PATH = ROOT / "crates/franken-node/src/supply_chain/quarantine.rs"
MOD_PATH = ROOT / "crates/franken-node/src/supply_chain/mod.rs"

EVIDENCE_DIR = ROOT / "artifacts/section_10_4/bd-1vm"
EVIDENCE_PATH = EVIDENCE_DIR / "verification_evidence.json"
SUMMARY_PATH = EVIDENCE_DIR / "verification_summary.md"

REQUIRED_INVARIANTS = [
    "INV-QUAR-MODES",
    "INV-QUAR-FAST-PATH",
    "INV-QUAR-FAIL-CLOSED",
    "INV-QUAR-DURABLE",
    "INV-QUAR-LIFECYCLE",
    "INV-QUAR-CLEARANCE",
    "INV-QUAR-RECALL-VERIFY",
    "INV-QUAR-AUDIT",
]

REQUIRED_RUST_SYMBOLS = [
    "pub enum QuarantineMode",
    "pub enum QuarantineSeverity",
    "pub enum QuarantineScope",
    "pub struct QuarantineOrder",
    "pub enum QuarantineReason",
    "pub enum QuarantineState",
    "pub struct RecallOrder",
    "pub struct RecallReceipt",
    "pub struct QuarantineImpactReport",
    "pub struct QuarantineClearance",
    "pub struct QuarantineAuditEntry",
    "pub struct QuarantineRecord",
    "pub struct QuarantineRegistry",
    "pub struct QuarantineError",
]

REQUIRED_EVENT_CODES = [
    "QUARANTINE_INITIATED",
    "QUARANTINE_PROPAGATED",
    "QUARANTINE_ENFORCED",
    "QUARANTINE_DRAIN_STARTED",
    "QUARANTINE_DRAIN_COMPLETED",
    "QUARANTINE_LIFTED",
    "RECALL_TRIGGERED",
    "RECALL_ARTIFACT_REMOVED",
    "RECALL_RECEIPT_EMITTED",
    "RECALL_COMPLETED",
]

REQUIRED_ERROR_CODES = [
    "ERR_QUARANTINE_NOT_FOUND",
    "ERR_QUARANTINE_ALREADY_ACTIVE",
    "ERR_RECALL_WITHOUT_QUARANTINE",
    "ERR_LIFT_REQUIRES_CLEARANCE",
    "ERR_AUDIT_CHAIN_BROKEN",
]

REQUIRED_REGISTRY_METHODS = [
    "pub fn initiate_quarantine(",
    "pub fn record_propagation(",
    "pub fn enforce_quarantine(",
    "pub fn start_drain(",
    "pub fn complete_drain(",
    "pub fn generate_impact_report(",
    "pub fn trigger_recall(",
    "pub fn record_recall_receipt(",
    "pub fn complete_recall(",
    "pub fn lift_quarantine(",
    "pub fn is_quarantined(",
    "pub fn get_active_quarantine(",
    "pub fn get_record(",
    "pub fn recall_completion_pct(",
    "pub fn verify_audit_integrity(",
    "pub fn audit_trail(",
    "pub fn query_audit_by_extension(",
]

REQUIRED_TESTS = [
    "test_initiate_soft_quarantine",
    "test_initiate_hard_quarantine",
    "test_critical_fast_path_enforcement",
    "test_duplicate_quarantine_rejected",
    "test_propagation_transitions_state",
    "test_enforcement_and_drain_lifecycle",
    "test_lift_quarantine_with_clearance",
    "test_lift_without_justification_fails",
    "test_recall_lifecycle",
    "test_recall_without_quarantine_fails",
    "test_impact_report",
    "test_recall_completion_percentage",
    "test_audit_trail_integrity",
    "test_audit_trail_tamper_detection",
    "test_query_audit_by_extension",
    "test_publisher_scope_quarantine",
    "test_all_versions_scope",
    "test_state_history_tracked",
    "test_quarantine_reason_variants",
    "test_severity_ordering",
]

REQUIRED_QUARANTINE_REASONS = [
    "VulnerabilityDisclosure",
    "MalwareDetection",
    "SupplyChainAttack",
    "BehavioralAnomaly",
    "OperatorInitiated",
    "RevocationEvent",
    "PolicyTrigger",
]


def check_file_exists(path: Path) -> dict[str, Any]:
    exists = path.exists()
    return {
        "path": str(path.relative_to(ROOT)),
        "exists": exists,
        "size_bytes": path.stat().st_size if exists else 0,
    }


def check_content(name: str, path: Path, required: list[str]) -> dict[str, Any]:
    if not path.exists():
        return {"pass": False, "reason": f"{name} file not found", "found": [], "missing": required}
    content = path.read_text()
    found = [item for item in required if item in content]
    missing = [item for item in required if item not in content]
    return {"pass": len(missing) == 0, "found": found, "missing": missing}


def check_mod_registration() -> dict[str, Any]:
    if not MOD_PATH.exists():
        return {"pass": False, "reason": "mod.rs not found"}
    content = MOD_PATH.read_text()
    has_module = "pub mod quarantine;" in content
    return {"pass": has_module, "registered": has_module}


def check_state_machine() -> dict[str, Any]:
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found"}
    content = RUST_IMPL_PATH.read_text()
    states = ["Initiated", "Propagated", "Enforced", "Draining", "Isolated", "Lifted", "RecallTriggered", "RecallCompleted"]
    found = [s for s in states if s in content]
    return {
        "pass": len(found) == len(states),
        "found": found,
        "missing": [s for s in states if s not in found],
        "total_states": len(states),
    }


def check_hash_chain() -> dict[str, Any]:
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found"}
    content = RUST_IMPL_PATH.read_text()
    has_prev_hash = "prev_hash" in content
    has_entry_hash = "entry_hash" in content
    has_sha256 = "Sha256" in content
    has_verify = "verify_audit_integrity" in content
    return {
        "pass": all([has_prev_hash, has_entry_hash, has_sha256, has_verify]),
        "hash_chain": has_prev_hash and has_entry_hash,
        "sha256": has_sha256,
        "integrity_check": has_verify,
    }


def check_fast_path() -> dict[str, Any]:
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found"}
    content = RUST_IMPL_PATH.read_text()
    has_critical_check = "QuarantineSeverity::Critical" in content
    has_fast_path = "fast-path" in content.lower() or "fast_path" in content.lower()
    has_immediate = "immediate enforcement" in content.lower() or "Enforced" in content
    return {
        "pass": all([has_critical_check, has_immediate]),
        "critical_severity_check": has_critical_check,
        "fast_path_logic": has_fast_path,
        "immediate_enforcement": has_immediate,
    }


def run_all_checks() -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = {
        "files": {
            "spec": check_file_exists(SPEC_PATH),
            "rust_impl": check_file_exists(RUST_IMPL_PATH),
            "mod_rs": check_file_exists(MOD_PATH),
        },
        "spec_invariants": check_content("spec", SPEC_PATH, REQUIRED_INVARIANTS),
        "rust_symbols": check_content("rust", RUST_IMPL_PATH, REQUIRED_RUST_SYMBOLS),
        "event_codes": check_content("rust", RUST_IMPL_PATH, REQUIRED_EVENT_CODES),
        "error_codes": check_content("rust", RUST_IMPL_PATH, REQUIRED_ERROR_CODES),
        "registry_methods": check_content("rust", RUST_IMPL_PATH, REQUIRED_REGISTRY_METHODS),
        "tests": check_content("rust", RUST_IMPL_PATH, REQUIRED_TESTS),
        "quarantine_reasons": check_content("rust", RUST_IMPL_PATH, REQUIRED_QUARANTINE_REASONS),
        "mod_registration": check_mod_registration(),
        "state_machine": check_state_machine(),
        "hash_chain": check_hash_chain(),
        "fast_path": check_fast_path(),
    }

    check_results = [
        checks["spec_invariants"],
        checks["rust_symbols"],
        checks["event_codes"],
        checks["error_codes"],
        checks["registry_methods"],
        checks["tests"],
        checks["quarantine_reasons"],
        checks["mod_registration"],
        checks["state_machine"],
        checks["hash_chain"],
        checks["fast_path"],
    ]

    all_pass = all(c.get("pass", False) for c in check_results)
    file_pass = all(f["exists"] for f in checks["files"].values())
    passed_count = sum(1 for c in check_results if c.get("pass", False)) + (1 if file_pass else 0)

    return {
        "bead_id": "bd-1vm",
        "section": "10.4",
        "title": "Fast Quarantine/Recall Workflow for Compromised Artifacts",
        "timestamp": timestamp,
        "overall_pass": all_pass and file_pass,
        "checks": checks,
        "summary": {
            "total_checks": 12,
            "passed": passed_count,
            "failed": 12 - passed_count,
        },
    }


def write_evidence(evidence: dict[str, Any]) -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n")


def write_summary(evidence: dict[str, Any]) -> None:
    s = evidence["summary"]
    lines = [
        f"# Verification Summary: {evidence['title']}",
        "",
        f"**Bead:** {evidence['bead_id']} | **Section:** {evidence['section']}",
        f"**Timestamp:** {evidence['timestamp']}",
        f"**Overall:** {'PASS' if evidence['overall_pass'] else 'FAIL'}",
        f"**Checks:** {s['passed']}/{s['total_checks']} passed",
        "",
        "## Check Results",
        "",
    ]
    for name, result in sorted(evidence["checks"].items()):
        if name == "files":
            for fname, finfo in result.items():
                status = "PASS" if finfo["exists"] else "FAIL"
                lines.append(f"- **File {fname}:** {status} ({finfo['path']}, {finfo['size_bytes']} bytes)")
        else:
            status = "PASS" if result.get("pass", False) else "FAIL"
            lines.append(f"- **{name}:** {status}")
            if "missing" in result and result["missing"]:
                for m in result["missing"]:
                    lines.append(f"  - Missing: `{m}`")

    lines.extend(["", "## Artifacts", ""])
    lines.append(f"- Spec: `{SPEC_PATH.relative_to(ROOT)}`")
    lines.append(f"- Implementation: `{RUST_IMPL_PATH.relative_to(ROOT)}`")
    lines.append(f"- Evidence: `{EVIDENCE_PATH.relative_to(ROOT)}`")
    lines.append("")
    SUMMARY_PATH.write_text("\n".join(lines) + "\n")


def self_test() -> bool:
    evidence = run_all_checks()
    assert isinstance(evidence, dict)
    assert evidence["bead_id"] == "bd-1vm"
    assert "checks" in evidence
    assert "summary" in evidence
    expected = [
        "files", "spec_invariants", "rust_symbols", "event_codes",
        "error_codes", "registry_methods", "tests", "quarantine_reasons",
        "mod_registration", "state_machine", "hash_chain", "fast_path",
    ]
    for cat in expected:
        assert cat in evidence["checks"], f"missing check: {cat}"
    return True


def main() -> None:
    logger = configure_test_logging("check_quarantine_workflow")
    parser = argparse.ArgumentParser(description="Verify bd-1vm quarantine/recall workflow")
    parser.add_argument("--json", action="store_true", help="Output JSON evidence")
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("self_test passed")
        return

    evidence = run_all_checks()

    if args.json:
        print(json.dumps(evidence, indent=2))
    else:
        s = evidence["summary"]
        status = "PASS" if evidence["overall_pass"] else "FAIL"
        print(f"bd-1vm verification: {status} ({s['passed']}/{s['total_checks']} checks passed)")
        for name, result in sorted(evidence["checks"].items()):
            if name == "files":
                for fname, finfo in result.items():
                    sym = "+" if finfo["exists"] else "-"
                    print(f"  [{sym}] file:{fname} {finfo['path']}")
            else:
                sym = "+" if result.get("pass", False) else "-"
                print(f"  [{sym}] {name}")
                if "missing" in result and result["missing"]:
                    for m in result["missing"]:
                        print(f"       missing: {m}")

    write_evidence(evidence)
    write_summary(evidence)


if __name__ == "__main__":
    main()
