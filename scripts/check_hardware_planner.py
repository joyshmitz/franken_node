#!/usr/bin/env python3
"""bd-2o8b: Heterogeneous hardware planner with policy-evidenced placements -- verification gate.

Usage:
    python3 scripts/check_hardware_planner.py            # human-readable
    python3 scripts/check_hardware_planner.py --json     # machine-readable JSON
    python3 scripts/check_hardware_planner.py --self-test # self-test mode
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SRC = ROOT / "crates" / "franken-node" / "src" / "runtime" / "hardware_planner.rs"
MOD = ROOT / "crates" / "franken-node" / "src" / "runtime" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_17" / "bd-2o8b_contract.md"
TEST_SUITE = ROOT / "tests" / "test_check_hardware_planner.py"
EVIDENCE = ROOT / "artifacts" / "section_10_17" / "bd-2o8b" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_17" / "bd-2o8b" / "verification_summary.md"

BEAD = "bd-2o8b"
SECTION = "10.17"

EVENT_CODES = [
    "HWP-001", "HWP-002", "HWP-003", "HWP-004", "HWP-005",
    "HWP-006", "HWP-007", "HWP-008", "HWP-009", "HWP-010",
    "HWP-011", "HWP-012",
]

ERROR_CODES = [
    "ERR_HWP_NO_CAPABLE_TARGET",
    "ERR_HWP_RISK_EXCEEDED",
    "ERR_HWP_CAPACITY_EXHAUSTED",
    "ERR_HWP_DUPLICATE_PROFILE",
    "ERR_HWP_DUPLICATE_POLICY",
    "ERR_HWP_UNKNOWN_PROFILE",
    "ERR_HWP_EMPTY_CAPABILITIES",
    "ERR_HWP_DISPATCH_UNGATED",
    "ERR_HWP_INVALID_RISK_LEVEL",
    "ERR_HWP_FALLBACK_EXHAUSTED",
]

INVARIANTS = [
    "INV-HWP-DETERMINISTIC",
    "INV-HWP-CAPABILITY-MATCH",
    "INV-HWP-RISK-BOUND",
    "INV-HWP-EVIDENCE-COMPLETE",
    "INV-HWP-FALLBACK-PATH",
    "INV-HWP-DISPATCH-GATED",
    "INV-HWP-SCHEMA-VERSIONED",
    "INV-HWP-AUDIT-COMPLETE",
]


def _safe_rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def _check(name: str, passed: bool, detail: str = "") -> dict:
    return {"check": name, "passed": passed, "detail": detail or ("found" if passed else "missing")}


def _read(p: Path) -> str:
    if not p.exists():
        return ""
    return p.read_text()


def _checks() -> list:
    results = []
    src = _read(SRC)
    mod_src = _read(MOD)

    # --- File existence ---
    results.append(_check("source file exists", SRC.exists(), _safe_rel(SRC)))
    results.append(_check("module wired in runtime/mod.rs",
                          "pub mod hardware_planner;" in mod_src,
                          "runtime/mod.rs contains pub mod hardware_planner"))
    results.append(_check("spec contract exists", SPEC.exists(), _safe_rel(SPEC)))
    results.append(_check("test suite exists", TEST_SUITE.exists(), _safe_rel(TEST_SUITE)))
    results.append(_check("verification evidence exists", EVIDENCE.exists(), _safe_rel(EVIDENCE)))
    results.append(_check("verification summary exists", SUMMARY.exists(), _safe_rel(SUMMARY)))

    # --- Core types ---
    results.append(_check("HardwarePlanner struct",
                          "struct HardwarePlanner" in src))
    results.append(_check("HardwareProfile struct",
                          "struct HardwareProfile" in src))
    results.append(_check("PlacementPolicy struct",
                          "struct PlacementPolicy" in src))
    results.append(_check("PlacementDecision struct",
                          "struct PlacementDecision" in src))
    results.append(_check("PolicyEvidence struct",
                          "struct PolicyEvidence" in src))
    results.append(_check("PlacementOutcome enum",
                          "enum PlacementOutcome" in src))
    results.append(_check("WorkloadRequest struct",
                          "struct WorkloadRequest" in src))
    results.append(_check("DispatchToken struct",
                          "struct DispatchToken" in src))
    results.append(_check("HardwarePlannerError enum",
                          "enum HardwarePlannerError" in src))

    # --- Key methods ---
    results.append(_check("register_profile function", "fn register_profile" in src))
    results.append(_check("register_policy function", "fn register_policy" in src))
    results.append(_check("request_placement function", "fn request_placement" in src))
    results.append(_check("dispatch function", "fn dispatch" in src))
    results.append(_check("release_slot function", "fn release_slot" in src))

    # --- BTreeMap / BTreeSet usage ---
    results.append(_check("BTreeMap used for deterministic ordering",
                          "BTreeMap" in src))
    results.append(_check("BTreeSet used for deterministic sets",
                          "BTreeSet" in src))

    # --- Event codes ---
    ec_found = sum(1 for ec in EVENT_CODES if ec in src)
    results.append(_check(
        f"event codes ({ec_found}/{len(EVENT_CODES)})",
        ec_found == len(EVENT_CODES),
        f"{ec_found}/{len(EVENT_CODES)}"))

    # --- Error codes ---
    err_found = sum(1 for ec in ERROR_CODES if ec in src)
    results.append(_check(
        f"error codes ({err_found}/{len(ERROR_CODES)})",
        err_found == len(ERROR_CODES),
        f"{err_found}/{len(ERROR_CODES)}"))

    # --- Invariant constants ---
    inv_found = sum(1 for inv in INVARIANTS if inv in src)
    results.append(_check(
        f"invariant constants ({inv_found}/{len(INVARIANTS)})",
        inv_found == len(INVARIANTS),
        f"{inv_found}/{len(INVARIANTS)}"))

    # --- Schema version ---
    results.append(_check("schema version hwp-v1.0", "hwp-v1.0" in src))

    # --- Serde derives ---
    results.append(_check("Serialize/Deserialize derives",
                          "Serialize" in src and "Deserialize" in src))

    # --- Unit tests ---
    test_count = len(re.findall(r"#\[test\]", src))
    results.append(_check(f"unit tests >= 20 ({test_count})", test_count >= 20, f"{test_count} tests"))

    # --- cfg(test) module ---
    results.append(_check("#[cfg(test)] module", "#[cfg(test)]" in src))

    # --- Fallback path ---
    results.append(_check("fallback path logic",
                          "fallback_attempted" in src and "fallback_reason" in src))

    # --- Dispatch gating ---
    results.append(_check("dispatch gating logic",
                          "approved_interfaces" in src and "DispatchUngated" in src))

    return results


def self_test():
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    return {
        "name": "hardware_planner_verification",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": len(checks) - passed,
        "checks": checks,
        "verdict": "PASS" if all(c["passed"] for c in checks) else "FAIL",
    }


def run_checks() -> dict:
    checks = _checks()
    passing = sum(1 for c in checks if c["passed"])
    failing = sum(1 for c in checks if not c["passed"])
    verdict = "PASS" if failing == 0 else "FAIL"

    return {
        "bead_id": BEAD,
        "title": "Heterogeneous hardware planner with policy-evidenced placements",
        "section": SECTION,
        "overall_pass": failing == 0,
        "verdict": verdict,
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": passing + failing,
        },
        "checks": checks,
        "events": EVENT_CODES,
    }


def main():
    if "--self-test" in sys.argv:
        result = self_test()
        if result["verdict"] == "PASS":
            print("self_test passed")
            sys.exit(0)
        else:
            failures = [c for c in result["checks"] if not c["passed"]]
            detail = "; ".join(f"{c['check']}: {c['detail']}" for c in failures[:5])
            print(f"self_test failed: {detail}")
            sys.exit(1)

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["overall_pass"] else 1)

    for c in result["checks"]:
        status = "PASS" if c["passed"] else "FAIL"
        print(f"  [{status}] {c['check']}: {c['detail']}")

    passing = result["summary"]["passing"]
    total = result["summary"]["total"]
    print(f"\n{BEAD} verification: {result['verdict']} ({passing}/{total} checks pass)")
    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
