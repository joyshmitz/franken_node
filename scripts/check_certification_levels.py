#!/usr/bin/env python3
"""Verification script for bd-273 extension certification levels."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

SPEC_PATH = ROOT / "docs/specs/section_10_4/bd-273_contract.md"
RUST_IMPL_PATH = ROOT / "crates/franken-node/src/supply_chain/certification.rs"
MOD_PATH = ROOT / "crates/franken-node/src/supply_chain/mod.rs"

EVIDENCE_DIR = ROOT / "artifacts/section_10_4/bd-273"
EVIDENCE_PATH = EVIDENCE_DIR / "verification_evidence.json"
SUMMARY_PATH = EVIDENCE_DIR / "verification_summary.md"

REQUIRED_INVARIANTS = [
    "INV-CERT-LEVELS",
    "INV-CERT-DETERMINISTIC",
    "INV-CERT-POLICY-MAP",
    "INV-CERT-PROMOTION",
    "INV-CERT-DEMOTION",
    "INV-CERT-REGISTRY",
    "INV-CERT-DEPLOYMENT",
    "INV-CERT-AUDIT",
]

REQUIRED_RUST_SYMBOLS = [
    "pub enum CertificationLevel",
    "pub enum DeploymentContext",
    "pub enum CapabilityCategory",
    "pub struct CertificationInput",
    "pub struct CertificationResult",
    "pub struct CertificationRecord",
    "pub struct CertificationRegistry",
    "pub struct CertificationAuditEntry",
    "pub enum CertificationAuditEvent",
    "pub fn evaluate_certification",
    "pub fn is_capability_allowed",
    "pub fn capability_policy",
]

REQUIRED_EVENT_CODES = [
    "CERTIFICATION_EVALUATED",
    "CERTIFICATION_ASSIGNED",
    "CERTIFICATION_PROMOTED",
    "CERTIFICATION_DEMOTED",
    "CERTIFICATION_POLICY_ENFORCED",
    "CERTIFICATION_GATE_PASS",
    "CERTIFICATION_GATE_REJECT",
]

REQUIRED_LEVELS = [
    "Uncertified",
    "Basic",
    "Standard",
    "Verified",
    "Audited",
]

REQUIRED_CAPABILITIES = [
    "FileRead",
    "FileWrite",
    "NetworkAccess",
    "ProcessSpawn",
    "CryptoOperations",
    "SystemConfiguration",
]

REQUIRED_REGISTRY_METHODS = [
    "pub fn evaluate_and_register",
    "pub fn promote",
    "pub fn demote",
    "pub fn check_deployment_gate",
    "pub fn check_capability_gate",
    "pub fn get_record",
    "pub fn query_audit_trail",
    "pub fn verify_audit_integrity",
]

REQUIRED_TESTS = [
    "test_uncertified_without_publisher",
    "test_basic_with_publisher_and_manifest",
    "test_standard_with_provenance_and_reputation",
    "test_verified_with_build_and_coverage",
    "test_audited_with_attestation",
    "test_insufficient_coverage_blocks_verified",
    "test_deterministic_evaluation",
    "test_capability_policy_uncertified",
    "test_capability_policy_standard",
    "test_capability_policy_audited",
    "test_deployment_gate_development",
    "test_deployment_gate_production_rejects_basic",
    "test_promotion_adjacent_only",
    "test_demotion_on_trust_degradation",
    "test_audit_trail_integrity",
    "test_audit_query_by_extension",
    "test_level_ordering",
    "test_meets_minimum",
    "test_evaluation_explanation_present",
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
    has_module = "pub mod certification;" in content
    return {"pass": has_module, "registered": has_module}


def check_policy_matrix() -> dict[str, Any]:
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found"}
    content = RUST_IMPL_PATH.read_text()
    has_fn = "pub fn is_capability_allowed" in content
    has_policy_fn = "pub fn capability_policy" in content
    has_match = "match (capability, level)" in content
    return {
        "pass": all([has_fn, has_policy_fn, has_match]),
        "capability_check_fn": has_fn,
        "policy_fn": has_policy_fn,
        "match_implementation": has_match,
    }


def check_deployment_gates() -> dict[str, Any]:
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found"}
    content = RUST_IMPL_PATH.read_text()
    has_context = "pub enum DeploymentContext" in content
    has_min = "pub fn minimum_certification" in content
    has_gate = "pub fn check_deployment_gate" in content
    return {
        "pass": all([has_context, has_min, has_gate]),
        "deployment_context_enum": has_context,
        "minimum_certification": has_min,
        "gate_check": has_gate,
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
        "levels": check_content("rust", RUST_IMPL_PATH, REQUIRED_LEVELS),
        "capabilities": check_content("rust", RUST_IMPL_PATH, REQUIRED_CAPABILITIES),
        "registry_methods": check_content("rust", RUST_IMPL_PATH, REQUIRED_REGISTRY_METHODS),
        "tests": check_content("rust", RUST_IMPL_PATH, REQUIRED_TESTS),
        "mod_registration": check_mod_registration(),
        "policy_matrix": check_policy_matrix(),
        "deployment_gates": check_deployment_gates(),
        "hash_chain": check_hash_chain(),
    }

    check_results = [
        checks["spec_invariants"],
        checks["rust_symbols"],
        checks["event_codes"],
        checks["levels"],
        checks["capabilities"],
        checks["registry_methods"],
        checks["tests"],
        checks["mod_registration"],
        checks["policy_matrix"],
        checks["deployment_gates"],
        checks["hash_chain"],
    ]

    all_pass = all(c.get("pass", False) for c in check_results)
    file_pass = all(f["exists"] for f in checks["files"].values())
    passed_count = sum(1 for c in check_results if c.get("pass", False)) + (1 if file_pass else 0)

    return {
        "bead_id": "bd-273",
        "section": "10.4",
        "title": "Extension Certification Levels Tied to Policy Controls",
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
    assert evidence["bead_id"] == "bd-273"
    assert "checks" in evidence
    assert "summary" in evidence
    expected = [
        "files", "spec_invariants", "rust_symbols", "event_codes",
        "levels", "capabilities", "registry_methods", "tests",
        "mod_registration", "policy_matrix", "deployment_gates", "hash_chain",
    ]
    for cat in expected:
        assert cat in evidence["checks"], f"missing check: {cat}"
    return True


def main() -> None:
    logger = configure_test_logging("check_certification_levels")
    parser = argparse.ArgumentParser(description="Verify bd-273 certification levels")
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
        print(f"bd-273 verification: {status} ({s['passed']}/{s['total_checks']} checks passed)")
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
