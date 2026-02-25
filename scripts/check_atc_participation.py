#!/usr/bin/env python3
"""Verify bd-2yvw: Sybil-resistant participation controls for ATC federation.

Checks that the ATC participation weighting infrastructure is correctly
implemented: Rust module present with required types, event codes, invariants,
Sybil detection, weight computation, audit logging, spec contract.

Usage:
    python scripts/check_atc_participation.py
    python scripts/check_atc_participation.py --json
    python scripts/check_atc_participation.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path
from typing import Any


CHECKS: list[dict[str, Any]] = []

REQUIRED_TYPES = [
    "AttestationEvidence",
    "AttestationLevel",
    "StakeEvidence",
    "ReputationEvidence",
    "ParticipantIdentity",
    "ParticipationWeight",
    "WeightAuditRecord",
    "SybilCluster",
    "WeightingConfig",
    "ParticipationWeightEngine",
]

REQUIRED_EVENT_CODES = [
    "ATC-PART-001",
    "ATC-PART-002",
    "ATC-PART-003",
    "ATC-PART-004",
    "ATC-PART-005",
    "ATC-PART-006",
    "ATC-PART-007",
    "ATC-PART-008",
    "ATC-PART-ERR-001",
    "ATC-PART-ERR-002",
]

REQUIRED_INVARIANTS = [
    "INV-ATC-SYBIL-BOUND",
    "INV-ATC-WEIGHT-DETERMINISM",
    "INV-ATC-NEW-NODE-CAP",
    "INV-ATC-STAKE-MONOTONE",
    "INV-ATC-ATTESTATION-REQUIRED",
    "INV-ATC-AUDIT-COMPLETE",
    "INV-ATC-CLUSTER-ATTENUATION",
]

ATTESTATION_LEVELS = [
    ("SelfSigned", "0.1"),
    ("PeerVerified", "0.4"),
    ("VerifierBacked", "0.8"),
    ("AuthorityCertified", "1.0"),
]

WEIGHT_COMPONENTS = [
    "attestation_component",
    "stake_component",
    "reputation_component",
    "sybil_penalty",
    "final_weight",
]


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    CHECKS.append(entry)
    return entry


def _safe_rel(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


def _read_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Checks: Rust implementation
# ---------------------------------------------------------------------------

def check_rust_module_exists() -> None:
    path = ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_participation_weighting.rs"
    exists = path.is_file()
    _check("rust_module_exists", exists, _safe_rel(path) if exists else f"missing: {_safe_rel(path)}")


def check_federation_mod_registration() -> None:
    mod_rs = ROOT / "crates" / "franken-node" / "src" / "federation" / "mod.rs"
    src = _read_text(mod_rs)
    registered = "pub mod atc_participation_weighting;" in src
    _check("federation_mod_registration", registered,
           "atc_participation_weighting in federation/mod.rs" if registered else "NOT registered")


def check_main_federation_registration() -> None:
    main_rs = ROOT / "crates" / "franken-node" / "src" / "main.rs"
    src = _read_text(main_rs)
    registered = "pub mod federation;" in src
    _check("main_federation_registration", registered,
           "federation module registered in main.rs" if registered else "NOT registered in main.rs")


def check_required_types() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_participation_weighting.rs")
    for type_name in REQUIRED_TYPES:
        found = type_name in src
        _check(f"type_{type_name}", found,
               f"{type_name} defined" if found else f"{type_name} missing")


def check_event_codes() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_participation_weighting.rs")
    for code in REQUIRED_EVENT_CODES:
        found = f'"{code}"' in src
        _check(f"event_code_{code}", found,
               f"{code} defined" if found else f"{code} missing")


def check_invariants() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_participation_weighting.rs")
    for inv in REQUIRED_INVARIANTS:
        found = f'"{inv}"' in src
        _check(f"invariant_{inv}", found,
               f"{inv} defined" if found else f"{inv} missing")


def check_attestation_levels() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_participation_weighting.rs")
    for level_name, multiplier in ATTESTATION_LEVELS:
        found = level_name in src and multiplier in src
        _check(f"attestation_level_{level_name}", found,
               f"{level_name} ({multiplier})" if found else f"{level_name} missing")


def check_weight_components() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_participation_weighting.rs")
    for comp in WEIGHT_COMPONENTS:
        found = comp in src
        _check(f"weight_component_{comp}", found,
               f"{comp} present" if found else f"{comp} missing")


def check_sybil_detection() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_participation_weighting.rs")
    has_detect = "detect_sybil_clusters" in src
    has_cluster = "SybilCluster" in src
    has_attenuation = "sybil_attenuation_factor" in src
    passed = has_detect and has_cluster and has_attenuation
    _check("sybil_detection", passed,
           "Sybil detection with cluster attenuation" if passed else "Sybil detection incomplete")


def check_audit_logging() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_participation_weighting.rs")
    has_audit = "audit_log" in src
    has_export = "export_audit_json" in src
    has_hash = "content_hash" in src
    passed = has_audit and has_export and has_hash
    _check("audit_logging", passed,
           "audit log with JSON export and content hash" if passed else "audit logging incomplete")


def check_inline_tests() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_participation_weighting.rs")
    test_count = len(re.findall(r"#\[test\]", src))
    passed = test_count >= 15
    _check("inline_tests", passed, f"{test_count} inline tests (need >= 15)")


def check_weight_computation() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "federation" / "atc_participation_weighting.rs")
    has_compute = "fn compute_weights" in src
    has_single = "fn compute_single_weight" in src
    passed = has_compute and has_single
    _check("weight_computation", passed,
           "batch and single weight computation present" if passed else "weight computation missing")


# ---------------------------------------------------------------------------
# Checks: Spec contract
# ---------------------------------------------------------------------------

def check_spec_contract() -> None:
    path = ROOT / "docs" / "specs" / "section_10_19" / "bd-2yvw_contract.md"
    exists = path.is_file()
    _check("spec_contract", exists, _safe_rel(path) if exists else f"missing: {_safe_rel(path)}")


def check_spec_invariants() -> None:
    src = _read_text(ROOT / "docs" / "specs" / "section_10_19" / "bd-2yvw_contract.md")
    for inv in REQUIRED_INVARIANTS:
        found = inv in src
        _check(f"spec_{inv}", found,
               f"{inv} in spec" if found else f"{inv} missing from spec")


def check_spec_event_codes() -> None:
    src = _read_text(ROOT / "docs" / "specs" / "section_10_19" / "bd-2yvw_contract.md")
    for code in REQUIRED_EVENT_CODES:
        found = code in src
        _check(f"spec_event_{code}", found,
               f"{code} in spec" if found else f"{code} missing from spec")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all_checks() -> list[dict[str, Any]]:
    CHECKS.clear()

    # Rust implementation
    check_rust_module_exists()
    check_federation_mod_registration()
    check_main_federation_registration()
    check_required_types()
    check_event_codes()
    check_invariants()
    check_attestation_levels()
    check_weight_components()
    check_sybil_detection()
    check_audit_logging()
    check_inline_tests()
    check_weight_computation()

    # Spec contract
    check_spec_contract()
    check_spec_invariants()
    check_spec_event_codes()

    return CHECKS


def run_all() -> dict[str, Any]:
    checks = run_all_checks()
    total = len(checks)
    passed = sum(1 for c in checks if c["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-2yvw",
        "title": "Sybil-resistant participation controls for ATC federation",
        "section": "10.19",
        "gate": False,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "overall_pass": failed == 0,
        "total": total,
        "passed": passed,
        "failed": failed,
        "required_types": REQUIRED_TYPES,
        "event_codes": REQUIRED_EVENT_CODES,
        "invariants": REQUIRED_INVARIANTS,
        "checks": checks,
    }


def self_test() -> bool:
    checks = run_all_checks()
    if not checks:
        print("SELF-TEST FAIL: no checks returned", file=sys.stderr)
        return False

    required_keys = {"check", "pass", "detail"}
    for entry in checks:
        if not isinstance(entry, dict) or not required_keys.issubset(entry.keys()):
            print(f"SELF-TEST FAIL: malformed entry: {entry}", file=sys.stderr)
            return False

    print(f"SELF-TEST OK: {len(checks)} checks returned", file=sys.stderr)
    return True


def main() -> None:
    logger = configure_test_logging("check_atc_participation")
    parser = argparse.ArgumentParser(description="bd-2yvw: ATC participation weighting verification")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(0 if self_test() else 1)

    output = run_all()

    if args.json:
        print(json.dumps(output, indent=2))
    else:
        print(
            f"\n  ATC Participation Weighting: {'PASS' if output['overall_pass'] else 'FAIL'} "
            f"({output['passed']}/{output['total']})\n"
        )
        for entry in output["checks"]:
            mark = "+" if entry["pass"] else "x"
            print(f"  [{mark}] {entry['check']}: {entry['detail']}")

    sys.exit(0 if output["overall_pass"] else 1)


if __name__ == "__main__":
    main()
