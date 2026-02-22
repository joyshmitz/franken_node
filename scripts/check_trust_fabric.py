#!/usr/bin/env python3
"""Verification script for bd-5si: Trust Fabric Convergence Protocol.

Validates spec, Rust implementation, policy doc, invariants, event codes,
error codes, and tests for the trust fabric convergence protocol.

Usage:
    python scripts/check_trust_fabric.py          # human-readable
    python scripts/check_trust_fabric.py --json    # JSON output
    python scripts/check_trust_fabric.py --self-test  # self-test mode
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BEAD_ID = "bd-5si"
SECTION = "10.12"
TITLE = "Trust Fabric Convergence Protocol"

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_12" / "bd-5si_contract.md"
RUST_PATH = ROOT / "crates" / "franken-node" / "src" / "connector" / "trust_fabric.rs"
MOD_PATH = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"
POLICY_PATH = ROOT / "docs" / "policy" / "trust_fabric_convergence.md"
TEST_PATH = ROOT / "tests" / "test_check_trust_fabric.py"
EVIDENCE_PATH = ROOT / "artifacts" / "section_10_12" / "bd-5si" / "verification_evidence.json"
SUMMARY_PATH = ROOT / "artifacts" / "section_10_12" / "bd-5si" / "verification_summary.md"

EVENT_CODES = [
    "TFC-001", "TFC-002", "TFC-003", "TFC-004",
    "TFC-005", "TFC-006", "TFC-007", "TFC-008",
]

ERROR_CODES = [
    "ERR_TFC_INVALID_CONFIG",
    "ERR_TFC_STALE_STATE",
    "ERR_TFC_DIGEST_MISMATCH",
    "ERR_TFC_DEGRADED_REJECT",
    "ERR_TFC_ESCALATION_TIMEOUT",
    "ERR_TFC_PARTITION_DETECTED",
]

INVARIANTS = [
    "INV-TFC-MONOTONIC",
    "INV-TFC-REVOKE-FIRST",
    "INV-TFC-DEGRADED-DENY",
    "INV-TFC-CONVERGENCE",
]

REQUIRED_TYPES = [
    "TrustFabricConfig",
    "TrustStateVector",
    "TrustStateDelta",
    "TrustFabricNode",
    "TrustFabricFleet",
    "TrustFabricEvent",
    "TrustFabricError",
]

REQUIRED_METHODS = [
    "add_trust_card",
    "add_extension",
    "apply_revocation",
    "receive_gossip",
    "check_convergence",
    "confirm_convergence",
    "anti_entropy_sweep",
    "partition_heal",
    "convergence_lag",
    "gossip_round",
    "is_converged",
    "delta_from",
    "compute_digest",
]


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": passed, "detail": detail}


def _file_text(path: Path) -> str | None:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return None


def run_all() -> dict:
    checks: list[dict] = []

    # --- Spec checks ---
    spec_text = _file_text(SPEC_PATH)
    checks.append(_check(
        "spec_exists",
        spec_text is not None,
        f"{SPEC_PATH.relative_to(ROOT)} exists" if spec_text else "spec missing",
    ))

    if spec_text:
        for code in EVENT_CODES:
            checks.append(_check(
                f"spec_event:{code}",
                code in spec_text,
                f"{code} found in spec" if code in spec_text else f"{code} missing from spec",
            ))

        for inv in INVARIANTS:
            checks.append(_check(
                f"spec_invariant:{inv}",
                inv in spec_text,
                f"{inv} found in spec" if inv in spec_text else f"{inv} missing from spec",
            ))

        for code in ERROR_CODES:
            checks.append(_check(
                f"spec_error:{code}",
                code in spec_text,
                f"{code} found in spec" if code in spec_text else f"{code} missing from spec",
            ))

        # Check spec mentions required types (exact or snake_case or natural language)
        for typ in REQUIRED_TYPES:
            snake = typ.replace("TrustFabric", "trust_fabric").replace("TrustState", "trust_state")
            # Also check for natural language equivalents
            natural = typ.replace("TrustFabricConfig", "Configuration") \
                         .replace("TrustStateVector", "Trust State Vector") \
                         .replace("TrustStateDelta", "delta") \
                         .replace("TrustFabricNode", "node") \
                         .replace("TrustFabricFleet", "fleet") \
                         .replace("TrustFabricEvent", "Event") \
                         .replace("TrustFabricError", "Error")
            found = (typ in spec_text
                     or snake in spec_text
                     or snake in spec_text.lower()
                     or natural.lower() in spec_text.lower())
            checks.append(_check(
                f"spec_type:{typ}",
                found,
                f"{typ} referenced in spec" if found else f"{typ} not in spec",
            ))
    else:
        for code in EVENT_CODES:
            checks.append(_check(f"spec_event:{code}", False, "spec missing"))
        for inv in INVARIANTS:
            checks.append(_check(f"spec_invariant:{inv}", False, "spec missing"))
        for code in ERROR_CODES:
            checks.append(_check(f"spec_error:{code}", False, "spec missing"))
        for typ in REQUIRED_TYPES:
            checks.append(_check(f"spec_type:{typ}", False, "spec missing"))

    # --- Rust implementation checks ---
    rust_text = _file_text(RUST_PATH)
    checks.append(_check(
        "rust_exists",
        rust_text is not None,
        f"{RUST_PATH.relative_to(ROOT)} exists" if rust_text else "Rust file missing",
    ))

    if rust_text:
        # Event code constants
        for code in EVENT_CODES:
            found = f'"{code}"' in rust_text
            checks.append(_check(
                f"rust_event:{code}",
                found,
                f"{code} constant in Rust" if found else f"{code} not in Rust",
            ))

        # Error code constants
        for code in ERROR_CODES:
            found = f'"{code}"' in rust_text
            checks.append(_check(
                f"rust_error:{code}",
                found,
                f"{code} constant in Rust" if found else f"{code} not in Rust",
            ))

        # Invariant references
        for inv in INVARIANTS:
            found = inv in rust_text or inv.replace("-", "_") in rust_text
            checks.append(_check(
                f"rust_invariant:{inv}",
                found,
                f"{inv} in Rust" if found else f"{inv} not in Rust",
            ))

        # Required types
        for typ in REQUIRED_TYPES:
            found = f"pub struct {typ}" in rust_text or f"pub enum {typ}" in rust_text
            checks.append(_check(
                f"rust_type:{typ}",
                found,
                f"{typ} defined" if found else f"{typ} not defined",
            ))

        # Required methods/functions
        for method in REQUIRED_METHODS:
            found = f"fn {method}" in rust_text
            checks.append(_check(
                f"rust_method:{method}",
                found,
                f"{method} implemented" if found else f"{method} not found",
            ))

        # Test count (>= 30)
        test_count = len(re.findall(r"#\[test\]", rust_text))
        checks.append(_check(
            "rust_test_count",
            test_count >= 30,
            f"{test_count} tests (>= 30 required)",
        ))

        # Specific test categories
        test_categories = {
            "config_tests": "test_default_config_valid",
            "state_tests": "test_new_state_empty",
            "delta_tests": "test_identical_states_empty_delta",
            "gossip_tests": "test_gossip_merges_state",
            "degraded_tests": "test_degraded_mode_entry",
            "convergence_tests": "test_fleet_convergence",
            "anti_entropy_tests": "test_anti_entropy_repairs_missing",
            "partition_tests": "test_partition_heal",
            "error_tests": "test_error_display",
            "event_tests": "test_events_recorded",
        }
        for name, marker in test_categories.items():
            found = marker in rust_text
            checks.append(_check(
                f"rust_{name}",
                found,
                f"{name} present" if found else f"{name} missing",
            ))
    else:
        for code in EVENT_CODES:
            checks.append(_check(f"rust_event:{code}", False, "Rust file missing"))
        for code in ERROR_CODES:
            checks.append(_check(f"rust_error:{code}", False, "Rust file missing"))
        for inv in INVARIANTS:
            checks.append(_check(f"rust_invariant:{inv}", False, "Rust file missing"))
        for typ in REQUIRED_TYPES:
            checks.append(_check(f"rust_type:{typ}", False, "Rust file missing"))
        for method in REQUIRED_METHODS:
            checks.append(_check(f"rust_method:{method}", False, "Rust file missing"))
        checks.append(_check("rust_test_count", False, "Rust file missing"))
        for name in ["config_tests", "state_tests", "delta_tests", "gossip_tests",
                      "degraded_tests", "convergence_tests", "anti_entropy_tests",
                      "partition_tests", "error_tests", "event_tests"]:
            checks.append(_check(f"rust_{name}", False, "Rust file missing"))

    # --- Module registration ---
    mod_text = _file_text(MOD_PATH)
    registered = mod_text is not None and "pub mod trust_fabric;" in mod_text
    checks.append(_check(
        "mod_registered",
        registered,
        "trust_fabric registered in connector/mod.rs" if registered else "not registered",
    ))

    # --- Policy doc ---
    policy_text = _file_text(POLICY_PATH)
    checks.append(_check(
        "policy_exists",
        policy_text is not None,
        f"{POLICY_PATH.relative_to(ROOT)} exists" if policy_text else "policy doc missing",
    ))
    if policy_text:
        policy_topics = {
            "degraded_mode": ["Degraded-Mode", "Degraded Mode", "degraded mode"],
            "revocation_first": ["Revocation-First", "revocation-first", "Revocations MUST be propagated before"],
            "anti_entropy": ["Anti-Entropy", "anti-entropy"],
            "partition_healing": ["Partition Healing", "partition heal"],
            "gossip": ["gossip-based", "Gossip", "gossip round"],
            "convergence_lag": ["convergence lag", "convergence_lag", "Convergence lag"],
            "max_degraded": ["max_degraded", "maximum duration", "300s", "300 seconds"],
        }
        for topic, patterns in policy_topics.items():
            found = any(p in policy_text for p in patterns)
            checks.append(_check(
                f"policy_topic:{topic}",
                found,
                f"'{topic}' covered in policy" if found else f"'{topic}' not in policy",
            ))
    else:
        policy_topics = {
            "degraded_mode": [], "revocation_first": [], "anti_entropy": [],
            "partition_healing": [], "gossip": [], "convergence_lag": [], "max_degraded": [],
        }
        for topic in policy_topics:
            checks.append(_check(f"policy_topic:{topic}", False, "policy doc missing"))

    # --- Python test file ---
    test_text = _file_text(TEST_PATH)
    checks.append(_check(
        "test_file_exists",
        test_text is not None,
        f"{TEST_PATH.relative_to(ROOT)} exists" if test_text else "test file missing",
    ))

    # --- Evidence artifacts ---
    evidence_text = _file_text(EVIDENCE_PATH)
    checks.append(_check(
        "evidence_exists",
        evidence_text is not None,
        "evidence JSON exists" if evidence_text else "evidence missing",
    ))

    summary_text = _file_text(SUMMARY_PATH)
    checks.append(_check(
        "summary_exists",
        summary_text is not None,
        "verification summary exists" if summary_text else "summary missing",
    ))

    # --- Compile result ---
    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])
    total = len(checks)
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "checks": checks,
        "passed": passed,
        "failed": failed,
        "total": total,
        "verdict": verdict,
        "all_passed": failed == 0,
        "status": "pass" if failed == 0 else "fail",
    }


def self_test() -> bool:
    """Verify the checker itself is well-formed."""
    result = run_all()
    assert isinstance(result, dict)
    assert result["bead_id"] == BEAD_ID
    assert result["section"] == SECTION
    assert isinstance(result["checks"], list)
    assert isinstance(result["total"], int)
    assert result["total"] > 0
    for check in result["checks"]:
        assert "name" in check
        assert "passed" in check
        assert "detail" in check
        assert isinstance(check["passed"], bool)
    return True


def main() -> None:
    if "--self-test" in sys.argv:
        ok = self_test()
        print("self_test passed" if ok else "self_test FAILED")
        sys.exit(0 if ok else 1)

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"=== {TITLE} ({BEAD_ID}) ===")
        print(f"Section: {SECTION}")
        print()
        for check in result["checks"]:
            status = "PASS" if check["passed"] else "FAIL"
            print(f"  [{status}] {check['name']}: {check['detail']}")
        print()
        print(f"Verdict: {result['verdict']} ({result['passed']}/{result['total']})")

    sys.exit(0 if result["all_passed"] else 1)


if __name__ == "__main__":
    main()
