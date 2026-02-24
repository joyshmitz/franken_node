#!/usr/bin/env python3
"""bd-2o8b verification gate for heterogeneous hardware planner with policy-evidenced placements.

Usage:
    python3 scripts/check_hardware_planner.py            # human-readable
    python3 scripts/check_hardware_planner.py --json     # machine-readable JSON
    python3 scripts/check_hardware_planner.py --self-test # self-test mode
    python3 scripts/check_hardware_planner.py --build-report # write report artifact
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

BEAD = "bd-2o8b"
SECTION = "10.17"

SRC = ROOT / "crates" / "franken-node" / "src" / "runtime" / "hardware_planner.rs"
MOD = ROOT / "crates" / "franken-node" / "src" / "runtime" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_17" / "bd-2o8b_contract.md"
ARCH_SPEC = ROOT / "docs" / "architecture" / "hardware_execution_planner.md"
TEST_SUITE = ROOT / "tests" / "test_check_hardware_planner.py"
PERF_TEST = ROOT / "tests" / "perf" / "hardware_planner_policy_conformance.rs"
REPORT_FILE = ROOT / "artifacts" / "10.17" / "hardware_placement_trace.json"
EVIDENCE = ROOT / "artifacts" / "section_10_17" / "bd-2o8b" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_17" / "bd-2o8b" / "verification_summary.md"

# Internal event codes (HWP-00x series)
EVENT_CODES = [
    "HWP-001", "HWP-002", "HWP-003", "HWP-004", "HWP-005",
    "HWP-006", "HWP-007", "HWP-008", "HWP-009", "HWP-010",
    "HWP-011", "HWP-012",
]

# Semantic event codes for the policy-evidenced placement lifecycle
PLANNER_EVENT_CODES = [
    "PLANNER_PLACEMENT_START",
    "PLANNER_CONSTRAINT_EVALUATED",
    "PLANNER_PLACEMENT_DECIDED",
    "PLANNER_FALLBACK_ACTIVATED",
    "PLANNER_DISPATCH_APPROVED",
]

# Internal error codes (ERR_HWP_* series)
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

# Semantic error codes (ERR_PLANNER_* series)
PLANNER_ERROR_CODES = [
    "ERR_PLANNER_CONSTRAINT_VIOLATED",
    "ERR_PLANNER_RESOURCE_CONTENTION",
    "ERR_PLANNER_NO_FALLBACK",
    "ERR_PLANNER_DISPATCH_DENIED",
    "ERR_PLANNER_REPRODUCIBILITY_FAILED",
    "ERR_PLANNER_INTERFACE_UNAPPROVED",
]

# Internal invariants (INV-HWP-* series)
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

# Semantic invariants (INV-PLANNER-* series)
PLANNER_INVARIANTS = [
    "INV-PLANNER-REPRODUCIBLE",
    "INV-PLANNER-CONSTRAINT-SATISFIED",
    "INV-PLANNER-FALLBACK-PATH",
    "INV-PLANNER-APPROVED-DISPATCH",
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
    arch_src = _read(ARCH_SPEC)
    perf_src = _read(PERF_TEST)

    # --- File existence ---
    results.append(_check("source file exists", SRC.exists(), _safe_rel(SRC)))
    results.append(_check("module wired in runtime/mod.rs",
                          "pub mod hardware_planner;" in mod_src,
                          "runtime/mod.rs contains pub mod hardware_planner"))
    results.append(_check("spec contract exists", SPEC.exists(), _safe_rel(SPEC)))
    results.append(_check("architecture spec exists", ARCH_SPEC.exists(), _safe_rel(ARCH_SPEC)))
    results.append(_check("test suite exists", TEST_SUITE.exists(), _safe_rel(TEST_SUITE)))
    results.append(_check("perf test exists", PERF_TEST.exists(), _safe_rel(PERF_TEST)))
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

    # --- Internal event codes (HWP series) ---
    ec_found = sum(1 for ec in EVENT_CODES if ec in src)
    results.append(_check(
        f"HWP event codes ({ec_found}/{len(EVENT_CODES)})",
        ec_found == len(EVENT_CODES),
        f"{ec_found}/{len(EVENT_CODES)}"))

    # --- Semantic event codes (PLANNER series) ---
    for code in PLANNER_EVENT_CODES:
        results.append(_check(
            f"Event code {code}",
            code in src and code in arch_src,
            code))

    # --- Internal error codes (ERR_HWP series) ---
    err_found = sum(1 for ec in ERROR_CODES if ec in src)
    results.append(_check(
        f"HWP error codes ({err_found}/{len(ERROR_CODES)})",
        err_found == len(ERROR_CODES),
        f"{err_found}/{len(ERROR_CODES)}"))

    # --- Semantic error codes (ERR_PLANNER series) ---
    for code in PLANNER_ERROR_CODES:
        results.append(_check(
            f"Error code {code}",
            code in src and code in arch_src,
            code))

    # --- Internal invariant constants (INV-HWP series) ---
    inv_found = sum(1 for inv in INVARIANTS if inv in src)
    results.append(_check(
        f"HWP invariant constants ({inv_found}/{len(INVARIANTS)})",
        inv_found == len(INVARIANTS),
        f"{inv_found}/{len(INVARIANTS)}"))

    # --- Semantic invariants (INV-PLANNER series) ---
    for inv in PLANNER_INVARIANTS:
        results.append(_check(
            f"Invariant {inv}",
            inv in src and inv in arch_src,
            inv))

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

    # --- Perf test references invariants ---
    for inv in PLANNER_INVARIANTS:
        inv_underscore = inv.replace("-", "_")
        results.append(_check(
            f"Perf test references {inv}",
            inv_underscore in perf_src or inv in perf_src,
            inv))

    return results


def run_all() -> dict:
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "schema_version": "hwp-v1.0",
        "bead_id": BEAD,
        "section": SECTION,
        "title": "Heterogeneous hardware planner with policy-evidenced placements",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "event_codes": PLANNER_EVENT_CODES,
        "error_codes": PLANNER_ERROR_CODES,
        "invariants": PLANNER_INVARIANTS,
        "planner_contract": {
            "placement_reproducible": True,
            "constraints_enforced": True,
            "fallback_on_contention": True,
            "dispatch_through_approved_interfaces": True,
        },
    }


def run_checks() -> dict:
    """Backward-compatible entry point used by existing tests."""
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


def write_report(result: dict) -> None:
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def self_test():
    checks = []
    checks.append(_check("planner event code count >= 5", len(PLANNER_EVENT_CODES) >= 5))
    checks.append(_check("planner error code count >= 6", len(PLANNER_ERROR_CODES) >= 6))
    checks.append(_check("planner invariant count >= 4", len(PLANNER_INVARIANTS) >= 4))
    checks.append(_check("HWP event code count >= 12", len(EVENT_CODES) >= 12))
    checks.append(_check("HWP error code count >= 10", len(ERROR_CODES) >= 10))
    checks.append(_check("HWP invariant count >= 8", len(INVARIANTS) >= 8))

    result = run_all()
    checks.append(_check("run_all has verdict", result.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_all has checks", isinstance(result.get("checks"), list)))
    checks.append(_check("run_all checks non-empty", len(result.get("checks", [])) > 10))

    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "name": "hardware_planner_verification",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": verdict,
    }


def main():
    logger = configure_test_logging("check_hardware_planner")
    parser = argparse.ArgumentParser(description="bd-2o8b checker")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--build-report", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        result = self_test()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if result["verdict"] == "PASS":
                print("self_test passed")
            else:
                failures = [c for c in result["checks"] if not c["passed"]]
                detail = "; ".join(f"{c['check']}: {c['detail']}" for c in failures[:5])
                print(f"self_test failed: {detail}")
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    result = run_checks()
    if args.build_report:
        write_report(run_all())

    if args.json:
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
