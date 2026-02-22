#!/usr/bin/env python3
"""Verification script for bd-2ah: obligation-tracked two-phase channel contracts."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BEAD_ID = "bd-2ah"
SECTION = "10.11"
TITLE = "Obligation-Tracked Two-Phase Channel Contracts"

SOURCE_RS = ROOT / "crates" / "franken-node" / "src" / "runtime" / "obligation_channel.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "runtime" / "mod.rs"
SPEC_PATH = ROOT / "docs" / "specs" / "section_10_11" / "bd-2ah_contract.md"
TEST_SUITE = ROOT / "tests" / "test_check_obligation_channel_protocol.py"
EVIDENCE_PATH = ROOT / "artifacts" / "section_10_11" / "bd-2ah" / "verification_evidence.json"
SUMMARY_PATH = ROOT / "artifacts" / "section_10_11" / "bd-2ah" / "verification_summary.md"

EVENT_CODES = [
    "FN-OB-001",
    "FN-OB-002",
    "FN-OB-003",
    "FN-OB-004",
    "FN-OB-005",
    "FN-OB-006",
    "FN-OB-007",
    "FN-OB-008",
    "FN-OB-009",
    "FN-OB-010",
    "FN-OB-011",
    "FN-OB-012",
]

ERROR_CODES = [
    "ERR_OCH_NOT_FOUND",
    "ERR_OCH_ALREADY_FULFILLED",
    "ERR_OCH_ALREADY_REJECTED",
    "ERR_OCH_TIMED_OUT",
    "ERR_OCH_CANCELLED",
    "ERR_OCH_PREPARE_FAILED",
    "ERR_OCH_COMMIT_FAILED",
    "ERR_OCH_ROLLBACK_FAILED",
    "ERR_OCH_DEADLINE_EXCEEDED",
    "ERR_OCH_INVALID_TRANSITION",
]

INVARIANTS = [
    "INV-OCH-TRACKED",
    "INV-OCH-DEADLINE",
    "INV-OCH-LEDGER-COMPLETE",
    "INV-OCH-CLOSURE-SIGNED",
    "INV-OCH-TWO-PHASE",
    "INV-OCH-ROLLBACK-ATOMIC",
]

REQUIRED_TYPES = [
    "ObligationChannel",
    "ObligationLedger",
    "TwoPhaseFlow",
    "ChannelObligation",
    "ObligationStatus",
    "TimeoutPolicy",
    "ClosureProof",
    "PrepareResult",
    "CommitResult",
    "ChannelAuditRecord",
]

REQUIRED_METHODS = [
    "send",
    "fulfill",
    "reject",
    "prepare",
    "commit",
    "rollback",
    "query_outstanding",
    "cancel",
    "sweep_timeouts",
    "generate_closure_proof",
]

MIN_TESTS = 15


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"check": name, "passed": bool(passed), "detail": detail}


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _has_type(source: str, name: str) -> bool:
    patterns = [
        rf"pub\s+struct\s+{name}\b",
        rf"pub\s+enum\s+{name}\b",
        rf"pub\s+trait\s+{name}\b",
        rf"struct\s+{name}\b",
        rf"enum\s+{name}\b",
        rf"trait\s+{name}\b",
    ]
    return any(re.search(p, source) for p in patterns)


def _has_method(source: str, name: str) -> bool:
    return bool(re.search(rf"fn\s+{name}\b", source))


def _checks():
    source = _read(SOURCE_RS)
    mod_rs = _read(MOD_RS)
    spec = _read(SPEC_PATH)

    results = []

    # --- File existence checks ---
    results.append(
        _check("source_file_exists", SOURCE_RS.is_file(), str(SOURCE_RS.relative_to(ROOT)))
    )
    results.append(
        _check(
            "module_wired_in_mod_rs",
            "pub mod obligation_channel;" in mod_rs,
            "runtime/mod.rs exports obligation_channel",
        )
    )
    results.append(
        _check("spec_contract_exists", SPEC_PATH.is_file(), str(SPEC_PATH.relative_to(ROOT)))
    )
    results.append(
        _check("test_suite_exists", TEST_SUITE.is_file(), str(TEST_SUITE.relative_to(ROOT)))
    )
    results.append(
        _check(
            "verification_evidence_exists",
            EVIDENCE_PATH.is_file(),
            str(EVIDENCE_PATH.relative_to(ROOT)),
        )
    )
    results.append(
        _check(
            "verification_summary_exists",
            SUMMARY_PATH.is_file(),
            str(SUMMARY_PATH.relative_to(ROOT)),
        )
    )

    # --- Type checks ---
    for name in REQUIRED_TYPES:
        results.append(
            _check(
                f"type:{name}",
                _has_type(source, name),
                f"{name} present in obligation_channel.rs",
            )
        )

    # --- Method checks ---
    for name in REQUIRED_METHODS:
        results.append(
            _check(
                f"method:{name}",
                _has_method(source, name),
                f"fn {name} exists in obligation_channel.rs",
            )
        )

    # --- Event code checks ---
    for code in EVENT_CODES:
        results.append(
            _check(
                f"event_code:{code}",
                code in source,
                f"{code} declared in obligation_channel.rs",
            )
        )

    # --- Error code checks ---
    for code in ERROR_CODES:
        results.append(
            _check(
                f"error_code:{code}",
                code in source,
                f"{code} declared in obligation_channel.rs",
            )
        )

    # --- Invariant checks ---
    for inv in INVARIANTS:
        results.append(
            _check(
                f"invariant:{inv}",
                inv in source,
                f"{inv} present in obligation_channel.rs",
            )
        )

    # --- Invariants in spec ---
    for inv in INVARIANTS:
        results.append(
            _check(
                f"spec_invariant:{inv}",
                inv in spec,
                f"{inv} present in spec contract",
            )
        )

    # --- Event codes in spec ---
    for code in EVENT_CODES:
        results.append(
            _check(
                f"spec_event:{code}",
                code in spec,
                f"{code} present in spec contract",
            )
        )

    # --- Error codes in spec ---
    for code in ERROR_CODES:
        results.append(
            _check(
                f"spec_error:{code}",
                code in spec,
                f"{code} present in spec contract",
            )
        )

    # --- Schema version ---
    results.append(
        _check(
            "schema_version",
            'och-v1.0' in source,
            "schema version och-v1.0 present",
        )
    )

    # --- Serde derives ---
    results.append(
        _check(
            "serde_derives",
            "Serialize" in source and "Deserialize" in source,
            "Serialize/Deserialize derives present",
        )
    )

    # --- BTreeMap usage ---
    results.append(
        _check(
            "btreemap_usage",
            "BTreeMap" in source,
            "BTreeMap used for ordered collections",
        )
    )

    # --- Unit tests ---
    test_count = len(re.findall(r"#\[test\]", source))
    results.append(
        _check(
            "unit_test_count",
            test_count >= MIN_TESTS,
            f"{test_count} tests (>= {MIN_TESTS})",
        )
    )

    results.append(
        _check(
            "cfg_test_module",
            "#[cfg(test)]" in source,
            "#[cfg(test)] module present",
        )
    )

    return results


def self_test():
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    return {
        "name": "obligation_channel_protocol_verification",
        "bead": BEAD_ID,
        "section": SECTION,
        "passed": passed,
        "failed": len(checks) - passed,
        "checks": checks,
        "verdict": "PASS" if all(c["passed"] for c in checks) else "FAIL",
    }


def run_all() -> dict:
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed

    return {
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "checks": checks,
        "passed": passed,
        "failed": failed,
        "total": len(checks),
        "status": "pass" if failed == 0 else "fail",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "all_passed": failed == 0,
    }


def main() -> None:
    as_json = "--json" in sys.argv

    if "--self-test" in sys.argv:
        result = self_test()
        assert result["verdict"] == "PASS", f"self_test failed: {result}"
        assert len(result["checks"]) >= 40
        for check in result["checks"]:
            assert "check" in check
            assert "passed" in check
            assert "detail" in check
        print("self_test passed")
        return

    result = run_all()

    if as_json:
        print(json.dumps(result, indent=2))
    else:
        for check in result["checks"]:
            marker = "PASS" if check["passed"] else "FAIL"
            print(f"[{marker}] {check['check']}: {check['detail']}")
        print(
            f"\n{BEAD_ID}: {result['passed']}/{result['total']} checks - {result['verdict']}"
        )

    sys.exit(0 if result["all_passed"] else 1)


if __name__ == "__main__":
    main()
