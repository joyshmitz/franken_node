#!/usr/bin/env python3
"""Verification script for bd-21fo: Self-Evolving Optimization Governor.

Validates spec, Rust implementation, event codes, invariants, core types,
error codes, methods, and test coverage.

Usage:
    python scripts/check_optimization_governor.py           # human-readable
    python scripts/check_optimization_governor.py --json     # JSON output
    python scripts/check_optimization_governor.py --self-test  # self-test mode
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


BEAD_ID = "bd-21fo"
SECTION = "10.17"
TITLE = "Self-Evolving Optimization Governor with Safety-Envelope Enforcement"

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_17" / "bd-21fo_contract.md"
RUST_PATH = ROOT / "crates" / "franken-node" / "src" / "runtime" / "optimization_governor.rs"
MOD_PATH = ROOT / "crates" / "franken-node" / "src" / "runtime" / "mod.rs"
TEST_PATH = ROOT / "tests" / "test_check_optimization_governor.py"
EVIDENCE_PATH = ROOT / "artifacts" / "section_10_17" / "bd-21fo" / "verification_evidence.json"
SUMMARY_PATH = ROOT / "artifacts" / "section_10_17" / "bd-21fo" / "verification_summary.md"
DECISION_LOG_PATH = ROOT / "artifacts" / "10.17" / "governor_decision_log.jsonl"

EVENT_CODES = [
    "GOV_001", "GOV_002", "GOV_003", "GOV_004", "GOV_005", "GOV_006", "GOV_007",
]

INVARIANTS = [
    "INV-GOV-ENVELOPE-NEVER-BREACHED",
    "INV-GOV-SHADOW-BEFORE-APPLY",
    "INV-GOV-EVIDENCE-ON-REJECT",
    "INV-GOV-KNOBS-ONLY",
    "INV-GOV-AUTO-REVERT",
    "INV-GOV-DETERMINISTIC-ORDER",
]

ERROR_CODES = [
    "ERR_GOV_ENVELOPE_VIOLATION",
    "ERR_GOV_NON_BENEFICIAL",
    "ERR_GOV_KNOB_LOCKED",
    "ERR_GOV_REVERT_FAILED",
    "ERR_GOV_SHADOW_TIMEOUT",
    "ERR_GOV_INVALID_PROPOSAL",
]

CORE_TYPES = [
    "SafetyEnvelope",
    "OptimizationProposal",
    "GovernorDecision",
    "DecisionLogEntry",
    "GovernorSnapshot",
    "ShadowEvalResult",
    "PredictedOutcome",
    "RuntimeKnob",
    "OptimizationGovernor",
]

REQUIRED_METHODS = [
    "shadow_evaluate",
    "submit_proposal",
    "auto_revert_check",
    "submit_shadow_only",
    "snapshot",
    "export_decision_log_jsonl",
    "export_verification_evidence",
    "update_envelope",
    "lock_knob",
    "unlock_knob",
    "knob_value",
    "decision_log",
    "decision_count",
]

RUNTIME_KNOB_VARIANTS = [
    "ConcurrencyLimit",
    "BatchSize",
    "CacheCapacity",
    "DrainTimeoutMs",
    "RetryBudget",
]

MIN_TEST_COUNT = 25


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": passed, "detail": detail}


def _file_text(path: Path) -> str | None:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return None


def run_all() -> dict:
    checks: list[dict] = []

    # --- SOURCE_EXISTS ---
    rust_text = _file_text(RUST_PATH)
    checks.append(_check(
        "SOURCE_EXISTS",
        rust_text is not None,
        f"{RUST_PATH.relative_to(ROOT)} exists" if rust_text else "optimization_governor.rs missing",
    ))

    # --- EVENT_CODES ---
    if rust_text:
        for code in EVENT_CODES:
            found = f'"{code}"' in rust_text
            checks.append(_check(
                f"EVENT_CODE:{code}",
                found,
                f"{code} found in Rust" if found else f"{code} missing from Rust",
            ))
    else:
        for code in EVENT_CODES:
            checks.append(_check(f"EVENT_CODE:{code}", False, "optimization_governor.rs missing"))

    # --- INVARIANTS ---
    if rust_text:
        for inv in INVARIANTS:
            found = inv in rust_text or inv.replace("-", "_") in rust_text
            checks.append(_check(
                f"INVARIANT:{inv}",
                found,
                f"{inv} found in Rust" if found else f"{inv} missing from Rust",
            ))
    else:
        for inv in INVARIANTS:
            checks.append(_check(f"INVARIANT:{inv}", False, "optimization_governor.rs missing"))

    # --- ERROR_CODES ---
    if rust_text:
        for code in ERROR_CODES:
            found = f'"{code}"' in rust_text or code in rust_text
            checks.append(_check(
                f"ERROR_CODE:{code}",
                found,
                f"{code} found in Rust" if found else f"{code} missing from Rust",
            ))
    else:
        for code in ERROR_CODES:
            checks.append(_check(f"ERROR_CODE:{code}", False, "optimization_governor.rs missing"))

    # --- CORE_TYPES ---
    if rust_text:
        for typ in CORE_TYPES:
            found = (f"pub struct {typ}" in rust_text
                     or f"pub enum {typ}" in rust_text
                     or f"pub type {typ}" in rust_text)
            checks.append(_check(
                f"CORE_TYPE:{typ}",
                found,
                f"{typ} defined" if found else f"{typ} not defined",
            ))
    else:
        for typ in CORE_TYPES:
            checks.append(_check(f"CORE_TYPE:{typ}", False, "optimization_governor.rs missing"))

    # --- RUNTIME_KNOB_VARIANTS ---
    if rust_text:
        for variant in RUNTIME_KNOB_VARIANTS:
            found = variant in rust_text
            checks.append(_check(
                f"KNOB_VARIANT:{variant}",
                found,
                f"{variant} variant present" if found else f"{variant} variant missing",
            ))
    else:
        for variant in RUNTIME_KNOB_VARIANTS:
            checks.append(_check(f"KNOB_VARIANT:{variant}", False, "optimization_governor.rs missing"))

    # --- REQUIRED_METHODS ---
    if rust_text:
        for method in REQUIRED_METHODS:
            found = f"fn {method}" in rust_text
            checks.append(_check(
                f"METHOD:{method}",
                found,
                f"{method} implemented" if found else f"{method} not found",
            ))
    else:
        for method in REQUIRED_METHODS:
            checks.append(_check(f"METHOD:{method}", False, "optimization_governor.rs missing"))

    # --- SCHEMA_VERSION ---
    if rust_text:
        found = '"gov-v1.0"' in rust_text
        checks.append(_check(
            "SCHEMA_VERSION",
            found,
            "gov-v1.0 declared" if found else "schema version missing",
        ))
    else:
        checks.append(_check("SCHEMA_VERSION", False, "optimization_governor.rs missing"))

    # --- SERDE_DERIVES ---
    if rust_text:
        found = "Serialize" in rust_text and "Deserialize" in rust_text
        checks.append(_check(
            "SERDE_DERIVES",
            found,
            "Serialize/Deserialize present" if found else "serde derives missing",
        ))
    else:
        checks.append(_check("SERDE_DERIVES", False, "optimization_governor.rs missing"))

    # --- TEST_COVERAGE ---
    if rust_text:
        test_count = len(re.findall(r"#\[test\]", rust_text))
        checks.append(_check(
            "TEST_COVERAGE",
            test_count >= MIN_TEST_COUNT,
            f"{test_count} tests (>= {MIN_TEST_COUNT} required)",
        ))
    else:
        checks.append(_check("TEST_COVERAGE", False, "optimization_governor.rs missing"))

    # --- MODULE_REGISTERED ---
    mod_text = _file_text(MOD_PATH)
    registered = mod_text is not None and "pub mod optimization_governor;" in mod_text
    checks.append(_check(
        "MODULE_REGISTERED",
        registered,
        "optimization_governor registered in runtime/mod.rs" if registered else "not registered",
    ))

    # --- SPEC_EXISTS ---
    spec_text = _file_text(SPEC_PATH)
    checks.append(_check(
        "SPEC_EXISTS",
        spec_text is not None,
        f"{SPEC_PATH.relative_to(ROOT)} exists" if spec_text else "spec contract missing",
    ))

    # Verify spec references key elements
    if spec_text:
        for code in EVENT_CODES:
            found = code in spec_text
            checks.append(_check(
                f"SPEC_EVENT:{code}",
                found,
                f"{code} in spec" if found else f"{code} missing from spec",
            ))
        for inv in INVARIANTS:
            found = inv in spec_text
            checks.append(_check(
                f"SPEC_INVARIANT:{inv}",
                found,
                f"{inv} in spec" if found else f"{inv} missing from spec",
            ))
        for code in ERROR_CODES:
            found = code in spec_text
            checks.append(_check(
                f"SPEC_ERROR:{code}",
                found,
                f"{code} in spec" if found else f"{code} missing from spec",
            ))
        for typ in CORE_TYPES:
            found = typ in spec_text
            checks.append(_check(
                f"SPEC_TYPE:{typ}",
                found,
                f"{typ} in spec" if found else f"{typ} missing from spec",
            ))
    else:
        for code in EVENT_CODES:
            checks.append(_check(f"SPEC_EVENT:{code}", False, "spec missing"))
        for inv in INVARIANTS:
            checks.append(_check(f"SPEC_INVARIANT:{inv}", False, "spec missing"))
        for code in ERROR_CODES:
            checks.append(_check(f"SPEC_ERROR:{code}", False, "spec missing"))
        for typ in CORE_TYPES:
            checks.append(_check(f"SPEC_TYPE:{typ}", False, "spec missing"))

    # --- TEST_FILE ---
    test_text = _file_text(TEST_PATH)
    checks.append(_check(
        "TEST_FILE_EXISTS",
        test_text is not None,
        f"{TEST_PATH.relative_to(ROOT)} exists" if test_text else "test file missing",
    ))

    # --- EVIDENCE ---
    evidence_text = _file_text(EVIDENCE_PATH)
    checks.append(_check(
        "EVIDENCE_EXISTS",
        evidence_text is not None,
        "evidence JSON exists" if evidence_text else "evidence missing",
    ))

    if evidence_text:
        try:
            ev = json.loads(evidence_text)
            checks.append(_check(
                "EVIDENCE_VALID_JSON",
                True,
                "evidence is valid JSON",
            ))
            has_bead = ev.get("bead_id") == BEAD_ID
            checks.append(_check(
                "EVIDENCE_BEAD_ID",
                has_bead,
                f"bead_id={ev.get('bead_id')}" if has_bead else "bead_id mismatch",
            ))
        except json.JSONDecodeError:
            checks.append(_check("EVIDENCE_VALID_JSON", False, "invalid JSON"))
            checks.append(_check("EVIDENCE_BEAD_ID", False, "cannot parse"))
    else:
        checks.append(_check("EVIDENCE_VALID_JSON", False, "evidence missing"))
        checks.append(_check("EVIDENCE_BEAD_ID", False, "evidence missing"))

    # --- SUMMARY ---
    summary_text = _file_text(SUMMARY_PATH)
    checks.append(_check(
        "SUMMARY_EXISTS",
        summary_text is not None,
        "verification summary exists" if summary_text else "summary missing",
    ))

    # --- DECISION_LOG ---
    decision_log_text = _file_text(DECISION_LOG_PATH)
    checks.append(_check(
        "DECISION_LOG_EXISTS",
        decision_log_text is not None,
        "governor_decision_log.jsonl exists" if decision_log_text else "decision log missing",
    ))

    if decision_log_text:
        lines = [l for l in decision_log_text.strip().split("\n") if l.strip()]
        valid_lines = 0
        for line in lines:
            try:
                json.loads(line)
                valid_lines += 1
            except json.JSONDecodeError:
                pass
        checks.append(_check(
            "DECISION_LOG_VALID_JSONL",
            valid_lines == len(lines) and valid_lines > 0,
            f"{valid_lines}/{len(lines)} valid JSONL lines",
        ))
    else:
        checks.append(_check("DECISION_LOG_VALID_JSONL", False, "decision log missing"))

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
    logger = configure_test_logging("check_optimization_governor")
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
