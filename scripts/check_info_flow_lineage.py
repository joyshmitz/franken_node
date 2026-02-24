#!/usr/bin/env python3
"""Verification script for bd-2iyk: information-flow lineage and exfiltration sentinel."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

BEAD_ID = "bd-2iyk"
SECTION = "10.17"
TITLE = "Information-Flow Lineage and Exfiltration Sentinel"

SOURCE_RS = ROOT / "crates" / "franken-node" / "src" / "security" / "lineage_tracker.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "security" / "mod.rs"
SPEC_PATH = ROOT / "docs" / "specs" / "section_10_17" / "bd-2iyk_contract.md"
TEST_SUITE = ROOT / "tests" / "test_check_info_flow_lineage.py"
EVIDENCE_PATH = ROOT / "artifacts" / "section_10_17" / "bd-2iyk" / "verification_evidence.json"
SUMMARY_PATH = ROOT / "artifacts" / "section_10_17" / "bd-2iyk" / "verification_summary.md"

EVENT_CODES = [
    "FN-IFL-001",
    "FN-IFL-002",
    "FN-IFL-003",
    "FN-IFL-004",
    "FN-IFL-005",
    "FN-IFL-006",
    "FN-IFL-007",
    "FN-IFL-008",
    "FN-IFL-009",
    "FN-IFL-010",
    "FN-IFL-011",
    "FN-IFL-012",
]

ERROR_CODES = [
    "ERR_IFL_LABEL_NOT_FOUND",
    "ERR_IFL_DUPLICATE_EDGE",
    "ERR_IFL_GRAPH_FULL",
    "ERR_IFL_BOUNDARY_INVALID",
    "ERR_IFL_CONTAINMENT_FAILED",
    "ERR_IFL_SNAPSHOT_FAILED",
    "ERR_IFL_QUERY_INVALID",
    "ERR_IFL_CONFIG_REJECTED",
    "ERR_IFL_ALREADY_QUARANTINED",
    "ERR_IFL_TIMEOUT",
]

INVARIANTS = [
    "INV-IFL-LABEL-PERSIST",
    "INV-IFL-EDGE-APPEND-ONLY",
    "INV-IFL-QUARANTINE-RECEIPT",
    "INV-IFL-BOUNDARY-ENFORCED",
    "INV-IFL-DETERMINISTIC",
    "INV-IFL-SNAPSHOT-FAITHFUL",
]

REQUIRED_TYPES = [
    "TaintLabel",
    "TaintSet",
    "FlowEdge",
    "LineageGraph",
    "ExfiltrationSentinel",
    "ExfiltrationAlert",
    "ContainmentReceipt",
    "TaintBoundary",
    "SentinelConfig",
    "FlowVerdict",
    "LineageQuery",
    "LineageSnapshot",
]

REQUIRED_METHODS = [
    "register_label",
    "assign_taint",
    "get_taint_set",
    "append_edge",
    "propagate_taint",
    "query",
    "snapshot",
    "evaluate_edge",
    "add_boundary",
    "health_check",
    "reload_config",
    "quarantine_edge",
]

MIN_TESTS = 20


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
            "pub mod lineage_tracker;" in mod_rs,
            "security/mod.rs exports lineage_tracker",
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
                f"{name} present in lineage_tracker.rs",
            )
        )

    # --- Method checks ---
    for name in REQUIRED_METHODS:
        results.append(
            _check(
                f"method:{name}",
                _has_method(source, name),
                f"fn {name} exists in lineage_tracker.rs",
            )
        )

    # --- Event code checks ---
    for code in EVENT_CODES:
        results.append(
            _check(
                f"event_code:{code}",
                code in source,
                f"{code} declared in lineage_tracker.rs",
            )
        )

    # --- Error code checks ---
    for code in ERROR_CODES:
        results.append(
            _check(
                f"error_code:{code}",
                code in source,
                f"{code} declared in lineage_tracker.rs",
            )
        )

    # --- Invariant checks ---
    for inv in INVARIANTS:
        results.append(
            _check(
                f"invariant:{inv}",
                inv in source,
                f"{inv} present in lineage_tracker.rs",
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
            "ifl-v1.0" in source,
            "schema version ifl-v1.0 present",
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

    # --- Invariants module ---
    results.append(
        _check(
            "invariants_module",
            "pub mod invariants" in source,
            "invariants module present",
        )
    )

    return results


def self_test():
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    return {
        "name": "info_flow_lineage_verification",
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
    logger = configure_test_logging("check_info_flow_lineage")
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
