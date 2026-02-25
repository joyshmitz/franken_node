#!/usr/bin/env python3
"""Verification script for bd-y0v: Operator Intelligence Recommendation Engine.

Validates spec, Rust implementation, policy doc, invariants, event codes,
error codes, and tests for the operator intelligence recommendation engine.

Usage:
    python scripts/check_operator_intelligence.py          # human-readable
    python scripts/check_operator_intelligence.py --json    # JSON output
    python scripts/check_operator_intelligence.py --self-test  # self-test mode
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path


BEAD_ID = "bd-y0v"
SECTION = "10.12"
TITLE = "Operator Intelligence Recommendation Engine"

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_12" / "bd-y0v_contract.md"
RUST_PATH = ROOT / "crates" / "franken-node" / "src" / "connector" / "operator_intelligence.rs"
MOD_PATH = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"
POLICY_PATH = ROOT / "docs" / "policy" / "operator_intelligence.md"
TEST_PATH = ROOT / "tests" / "test_check_operator_intelligence.py"
EVIDENCE_PATH = ROOT / "artifacts" / "section_10_12" / "bd-y0v" / "verification_evidence.json"
SUMMARY_PATH = ROOT / "artifacts" / "section_10_12" / "bd-y0v" / "verification_summary.md"

EVENT_CODES = [
    "OIR-001", "OIR-002", "OIR-003", "OIR-004", "OIR-005",
    "OIR-006", "OIR-007", "OIR-008", "OIR-009", "OIR-010",
]

ERROR_CODES = [
    "ERR_OIR_INVALID_CONFIG",
    "ERR_OIR_NO_CONTEXT",
    "ERR_OIR_SCORE_OVERFLOW",
    "ERR_OIR_ROLLBACK_FAILED",
    "ERR_OIR_REPLAY_MISMATCH",
    "ERR_OIR_DEGRADED",
]

INVARIANTS = [
    "INV-OIR-DETERMINISTIC",
    "INV-OIR-ROLLBACK-SOUND",
    "INV-OIR-BUDGET",
    "INV-OIR-AUDIT",
]

REQUIRED_TYPES = [
    "RecommendationConfig",
    "RecommendationEngine",
    "Recommendation",
    "OperatorContext",
    "RollbackProof",
    "ReplayArtifact",
    "AuditEntry",
    "OIEvent",
    "OIError",
]

REQUIRED_METHODS = [
    "recommend",
    "accept_recommendation",
    "reject_recommendation",
    "execute_recommendation",
    "execute_rollback",
    "mark_source_unavailable",
    "compute_expected_loss",
    "compute_confidence",
    "generate_actions",
    "fingerprint",
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
                f"{code} found in spec" if code in spec_text else f"{code} missing",
            ))
        for inv in INVARIANTS:
            checks.append(_check(
                f"spec_invariant:{inv}",
                inv in spec_text,
                f"{inv} found in spec" if inv in spec_text else f"{inv} missing",
            ))
        for code in ERROR_CODES:
            checks.append(_check(
                f"spec_error:{code}",
                code in spec_text,
                f"{code} found in spec" if code in spec_text else f"{code} missing",
            ))
    else:
        for code in EVENT_CODES:
            checks.append(_check(f"spec_event:{code}", False, "spec missing"))
        for inv in INVARIANTS:
            checks.append(_check(f"spec_invariant:{inv}", False, "spec missing"))
        for code in ERROR_CODES:
            checks.append(_check(f"spec_error:{code}", False, "spec missing"))

    # --- Rust implementation ---
    rust_text = _file_text(RUST_PATH)
    checks.append(_check(
        "rust_exists",
        rust_text is not None,
        f"{RUST_PATH.relative_to(ROOT)} exists" if rust_text else "Rust file missing",
    ))

    if rust_text:
        for code in EVENT_CODES:
            found = f'"{code}"' in rust_text
            checks.append(_check(f"rust_event:{code}", found,
                                 f"{code} in Rust" if found else f"{code} not in Rust"))
        for code in ERROR_CODES:
            found = f'"{code}"' in rust_text
            checks.append(_check(f"rust_error:{code}", found,
                                 f"{code} in Rust" if found else f"{code} not in Rust"))
        for inv in INVARIANTS:
            found = inv in rust_text or inv.replace("-", "_") in rust_text
            checks.append(_check(f"rust_invariant:{inv}", found,
                                 f"{inv} in Rust" if found else f"{inv} not in Rust"))
        for typ in REQUIRED_TYPES:
            found = f"pub struct {typ}" in rust_text or f"pub enum {typ}" in rust_text
            checks.append(_check(f"rust_type:{typ}", found,
                                 f"{typ} defined" if found else f"{typ} not defined"))
        for method in REQUIRED_METHODS:
            found = f"fn {method}" in rust_text
            checks.append(_check(f"rust_method:{method}", found,
                                 f"{method} implemented" if found else f"{method} not found"))

        test_count = len(re.findall(r"#\[test\]", rust_text))
        checks.append(_check("rust_test_count", test_count >= 30,
                             f"{test_count} tests (>= 30 required)"))

        test_categories = {
            "config_tests": "test_default_config_valid",
            "context_tests": "test_context_valid",
            "scoring_tests": "test_expected_loss_computation",
            "recommendation_tests": "test_recommend_produces_results",
            "determinism_tests": "test_recommend_deterministic",
            "audit_tests": "test_audit_trail_recorded",
            "budget_tests": "test_budget_enforcement",
            "rollback_tests": "test_rollback_proof_verify",
            "replay_tests": "test_replay_artifact_created",
            "degraded_tests": "test_degraded_mode_entry",
            "error_tests": "test_error_display",
        }
        for name, marker in test_categories.items():
            found = marker in rust_text
            checks.append(_check(f"rust_{name}", found,
                                 f"{name} present" if found else f"{name} missing"))
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
        for name in ["config_tests", "context_tests", "scoring_tests",
                      "recommendation_tests", "determinism_tests", "audit_tests",
                      "budget_tests", "rollback_tests", "replay_tests",
                      "degraded_tests", "error_tests"]:
            checks.append(_check(f"rust_{name}", False, "Rust file missing"))

    # --- Module registration ---
    mod_text = _file_text(MOD_PATH)
    registered = mod_text is not None and "pub mod operator_intelligence;" in mod_text
    checks.append(_check("mod_registered", registered,
                         "operator_intelligence registered" if registered else "not registered"))

    # --- Policy doc ---
    policy_text = _file_text(POLICY_PATH)
    checks.append(_check("policy_exists", policy_text is not None,
                         "policy doc exists" if policy_text else "policy doc missing"))
    if policy_text:
        topics = {
            "expected_loss": ["Expected-Loss", "expected-loss", "expected_loss"],
            "rollback_proof": ["Rollback Proof", "rollback proof", "rollback"],
            "replay": ["Replay", "replay artifact", "Deterministic Replay"],
            "audit_trail": ["Audit Trail", "audit trail"],
            "risk_budget": ["Risk Budget", "risk budget", "risk_budget"],
            "degraded_mode": ["Degraded Mode", "degraded mode", "Degraded"],
            "deterministic": ["deterministic", "Deterministic"],
        }
        for topic, patterns in topics.items():
            found = any(p in policy_text for p in patterns)
            checks.append(_check(f"policy_topic:{topic}", found,
                                 f"'{topic}' in policy" if found else f"'{topic}' not in policy"))
    else:
        for topic in ["expected_loss", "rollback_proof", "replay", "audit_trail",
                       "risk_budget", "degraded_mode", "deterministic"]:
            checks.append(_check(f"policy_topic:{topic}", False, "policy doc missing"))

    # --- Test file ---
    test_text = _file_text(TEST_PATH)
    checks.append(_check("test_file_exists", test_text is not None,
                         "test file exists" if test_text else "test file missing"))

    # --- Evidence ---
    evidence_text = _file_text(EVIDENCE_PATH)
    checks.append(_check("evidence_exists", evidence_text is not None,
                         "evidence JSON exists" if evidence_text else "evidence missing"))

    summary_text = _file_text(SUMMARY_PATH)
    checks.append(_check("summary_exists", summary_text is not None,
                         "summary exists" if summary_text else "summary missing"))

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
    result = run_all()
    assert isinstance(result, dict)
    assert result["bead_id"] == BEAD_ID
    assert result["section"] == SECTION
    assert isinstance(result["checks"], list)
    assert result["total"] > 0
    for check in result["checks"]:
        assert "name" in check
        assert "passed" in check
        assert "detail" in check
        assert isinstance(check["passed"], bool)
    return True


def main() -> None:
    logger = configure_test_logging("check_operator_intelligence")
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
