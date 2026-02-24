#!/usr/bin/env python3
"""Verification script for bd-3l2p: Intent-Aware Remote Effects Firewall.

Validates spec, Rust implementation, event codes, invariants, error codes,
core types, verdict pathways, and test coverage.

Usage:
    python scripts/check_intent_firewall.py              # human-readable
    python scripts/check_intent_firewall.py --json        # JSON output
    python scripts/check_intent_firewall.py --self-test   # self-test mode
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

BEAD_ID = "bd-3l2p"
SECTION = "10.17"
TITLE = "Intent-Aware Remote Effects Firewall"

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_17" / "bd-3l2p_contract.md"
RUST_PATH = (
    ROOT / "crates" / "franken-node" / "src" / "security" / "intent_firewall.rs"
)
MOD_PATH = ROOT / "crates" / "franken-node" / "src" / "security" / "mod.rs"
TEST_PATH = ROOT / "tests" / "test_check_intent_firewall.py"
EVIDENCE_PATH = (
    ROOT / "artifacts" / "section_10_17" / "bd-3l2p" / "verification_evidence.json"
)
SUMMARY_PATH = (
    ROOT / "artifacts" / "section_10_17" / "bd-3l2p" / "verification_summary.md"
)
EVAL_REPORT_PATH = ROOT / "artifacts" / "10.17" / "intent_firewall_eval_report.json"

# Event codes from the contract spec (FW_001 through FW_010).
EVENT_CODES = [
    "FW_001",
    "FW_002",
    "FW_003",
    "FW_004",
    "FW_005",
    "FW_006",
    "FW_007",
    "FW_008",
    "FW_009",
    "FW_010",
]

# Invariants from the contract spec.
INVARIANTS = [
    "INV-FW-FAIL-CLOSED",
    "INV-FW-RECEIPT-EVERY-DECISION",
    "INV-FW-RISKY-DEFAULT-DENY",
    "INV-FW-DETERMINISTIC",
    "INV-FW-EXTENSION-SCOPED",
]

# Error codes from the contract spec.
ERROR_CODES = [
    "ERR_FW_UNCLASSIFIED",
    "ERR_FW_NO_POLICY",
    "ERR_FW_INVALID_EFFECT",
    "ERR_FW_RECEIPT_FAILED",
    "ERR_FW_POLICY_CONFLICT",
    "ERR_FW_EXTENSION_UNKNOWN",
    "ERR_FW_OVERRIDE_UNAUTHORIZED",
    "ERR_FW_QUARANTINE_FULL",
]

# Core types that must be defined in Rust.
CORE_TYPES = [
    "IntentClassification",
    "IntentClassifier",
    "EffectsFirewall",
    "RemoteEffect",
    "FirewallVerdict",
    "FirewallDecision",
    "TrafficPolicy",
    "TrafficPolicyRule",
    "FirewallError",
    "FirewallAuditEvent",
    "TrafficOrigin",
    "PolicyOverride",
]

# Verdict pathways that must be represented.
VERDICTS = [
    "Allow",
    "Challenge",
    "Simulate",
    "Deny",
    "Quarantine",
]

# Required methods on the EffectsFirewall type.
REQUIRED_METHODS = [
    "fn new",
    "fn evaluate",
    "fn register_extension",
    "fn add_override",
    "fn audit_log",
    "fn quarantined",
    "fn generate_report",
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
    checks.append(
        _check(
            "SOURCE_EXISTS",
            rust_text is not None,
            f"{RUST_PATH.relative_to(ROOT)} exists"
            if rust_text
            else "intent_firewall.rs missing",
        )
    )

    # --- EVENT_CODES ---
    if rust_text:
        for code in EVENT_CODES:
            found = f'"{code}"' in rust_text
            checks.append(
                _check(
                    f"EVENT_CODE:{code}",
                    found,
                    f"{code} found in Rust" if found else f"{code} missing from Rust",
                )
            )
    else:
        for code in EVENT_CODES:
            checks.append(
                _check(
                    f"EVENT_CODE:{code}", False, "intent_firewall.rs missing"
                )
            )

    # --- INVARIANTS ---
    if rust_text:
        for inv in INVARIANTS:
            found = inv in rust_text or inv.replace("-", "_") in rust_text
            checks.append(
                _check(
                    f"INVARIANT:{inv}",
                    found,
                    f"{inv} found in Rust" if found else f"{inv} missing from Rust",
                )
            )
    else:
        for inv in INVARIANTS:
            checks.append(
                _check(f"INVARIANT:{inv}", False, "intent_firewall.rs missing")
            )

    # --- ERROR_CODES ---
    if rust_text:
        for code in ERROR_CODES:
            found = f'"{code}"' in rust_text or code in rust_text
            checks.append(
                _check(
                    f"ERROR_CODE:{code}",
                    found,
                    f"{code} found in Rust" if found else f"{code} missing from Rust",
                )
            )
    else:
        for code in ERROR_CODES:
            checks.append(
                _check(f"ERROR_CODE:{code}", False, "intent_firewall.rs missing")
            )

    # --- CORE_TYPES ---
    if rust_text:
        for typ in CORE_TYPES:
            found = (
                f"pub struct {typ}" in rust_text
                or f"pub enum {typ}" in rust_text
                or f"pub type {typ}" in rust_text
            )
            checks.append(
                _check(
                    f"CORE_TYPE:{typ}",
                    found,
                    f"{typ} defined" if found else f"{typ} not defined",
                )
            )
    else:
        for typ in CORE_TYPES:
            checks.append(
                _check(f"CORE_TYPE:{typ}", False, "intent_firewall.rs missing")
            )

    # --- VERDICTS ---
    if rust_text:
        for v in VERDICTS:
            found = v in rust_text
            checks.append(
                _check(
                    f"VERDICT:{v}",
                    found,
                    f"{v} verdict present" if found else f"{v} verdict missing",
                )
            )
    else:
        for v in VERDICTS:
            checks.append(
                _check(f"VERDICT:{v}", False, "intent_firewall.rs missing")
            )

    # --- REQUIRED_METHODS ---
    if rust_text:
        for method in REQUIRED_METHODS:
            found = method in rust_text
            checks.append(
                _check(
                    f"METHOD:{method}",
                    found,
                    f"{method} implemented" if found else f"{method} not found",
                )
            )
    else:
        for method in REQUIRED_METHODS:
            checks.append(
                _check(f"METHOD:{method}", False, "intent_firewall.rs missing")
            )

    # --- SCHEMA_VERSION ---
    if rust_text:
        found = '"fw-v1.0"' in rust_text
        checks.append(
            _check(
                "SCHEMA_VERSION",
                found,
                "fw-v1.0 declared" if found else "schema version missing",
            )
        )
    else:
        checks.append(
            _check("SCHEMA_VERSION", False, "intent_firewall.rs missing")
        )

    # --- SERDE_DERIVES ---
    if rust_text:
        found = "Serialize" in rust_text and "Deserialize" in rust_text
        checks.append(
            _check(
                "SERDE_DERIVES",
                found,
                "Serialize/Deserialize present" if found else "serde derives missing",
            )
        )
    else:
        checks.append(
            _check("SERDE_DERIVES", False, "intent_firewall.rs missing")
        )

    # --- BTREEMAP_DETERMINISM ---
    if rust_text:
        found = "BTreeMap" in rust_text and "BTreeSet" in rust_text
        checks.append(
            _check(
                "BTREEMAP_DETERMINISM",
                found,
                "BTreeMap/BTreeSet used for determinism"
                if found
                else "BTreeMap/BTreeSet missing",
            )
        )
    else:
        checks.append(
            _check("BTREEMAP_DETERMINISM", False, "intent_firewall.rs missing")
        )

    # --- TEST_COVERAGE ---
    if rust_text:
        test_count = len(re.findall(r"#\[test\]", rust_text))
        checks.append(
            _check(
                "TEST_COVERAGE",
                test_count >= MIN_TEST_COUNT,
                f"{test_count} tests (>= {MIN_TEST_COUNT} required)",
            )
        )
    else:
        checks.append(
            _check("TEST_COVERAGE", False, "intent_firewall.rs missing")
        )

    # --- MODULE_REGISTERED ---
    mod_text = _file_text(MOD_PATH)
    registered = mod_text is not None and "pub mod intent_firewall;" in mod_text
    checks.append(
        _check(
            "MODULE_REGISTERED",
            registered,
            "intent_firewall registered in security/mod.rs"
            if registered
            else "not registered",
        )
    )

    # --- SPEC_EXISTS ---
    spec_text = _file_text(SPEC_PATH)
    checks.append(
        _check(
            "SPEC_EXISTS",
            spec_text is not None,
            f"{SPEC_PATH.relative_to(ROOT)} exists"
            if spec_text
            else "spec contract missing",
        )
    )

    # Verify spec references key elements.
    if spec_text:
        for code in EVENT_CODES:
            found = code in spec_text
            checks.append(
                _check(
                    f"SPEC_EVENT:{code}",
                    found,
                    f"{code} in spec" if found else f"{code} missing from spec",
                )
            )
        for inv in INVARIANTS:
            found = inv in spec_text
            checks.append(
                _check(
                    f"SPEC_INVARIANT:{inv}",
                    found,
                    f"{inv} in spec" if found else f"{inv} missing from spec",
                )
            )
        for code in ERROR_CODES:
            found = code in spec_text
            checks.append(
                _check(
                    f"SPEC_ERROR:{code}",
                    found,
                    f"{code} in spec" if found else f"{code} missing from spec",
                )
            )
    else:
        for code in EVENT_CODES:
            checks.append(_check(f"SPEC_EVENT:{code}", False, "spec missing"))
        for inv in INVARIANTS:
            checks.append(_check(f"SPEC_INVARIANT:{inv}", False, "spec missing"))
        for code in ERROR_CODES:
            checks.append(_check(f"SPEC_ERROR:{code}", False, "spec missing"))

    # --- EVAL_REPORT ---
    eval_text = _file_text(EVAL_REPORT_PATH)
    checks.append(
        _check(
            "EVAL_REPORT_EXISTS",
            eval_text is not None,
            "intent_firewall_eval_report.json exists"
            if eval_text
            else "eval report missing",
        )
    )

    if eval_text:
        try:
            report = json.loads(eval_text)
            checks.append(
                _check(
                    "EVAL_REPORT_VALID_JSON",
                    True,
                    "eval report is valid JSON",
                )
            )
            has_verdict = "verdict" in report
            checks.append(
                _check(
                    "EVAL_REPORT_VERDICT",
                    has_verdict and report["verdict"] == "PASS",
                    f"verdict={report.get('verdict', 'MISSING')}"
                    if has_verdict
                    else "verdict field missing",
                )
            )
        except json.JSONDecodeError:
            checks.append(
                _check("EVAL_REPORT_VALID_JSON", False, "invalid JSON")
            )
            checks.append(
                _check("EVAL_REPORT_VERDICT", False, "cannot parse")
            )
    else:
        checks.append(
            _check("EVAL_REPORT_VALID_JSON", False, "eval report missing")
        )
        checks.append(
            _check("EVAL_REPORT_VERDICT", False, "eval report missing")
        )

    # --- TEST_FILE ---
    test_text = _file_text(TEST_PATH)
    checks.append(
        _check(
            "TEST_FILE_EXISTS",
            test_text is not None,
            f"{TEST_PATH.relative_to(ROOT)} exists"
            if test_text
            else "test file missing",
        )
    )

    # --- EVIDENCE ---
    evidence_text = _file_text(EVIDENCE_PATH)
    checks.append(
        _check(
            "EVIDENCE_EXISTS",
            evidence_text is not None,
            "evidence JSON exists" if evidence_text else "evidence missing",
        )
    )

    # --- SUMMARY ---
    summary_text = _file_text(SUMMARY_PATH)
    checks.append(
        _check(
            "SUMMARY_EXISTS",
            summary_text is not None,
            "verification summary exists" if summary_text else "summary missing",
        )
    )

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
    logger = configure_test_logging("check_intent_firewall")
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
