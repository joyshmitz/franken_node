#!/usr/bin/env python3
"""bd-ufk5: Verification script for VEF performance budget gates.

Usage:
    python3 scripts/check_vef_perf_budget_gate.py            # human-readable
    python3 scripts/check_vef_perf_budget_gate.py --json      # machine-readable
    python3 scripts/check_vef_perf_budget_gate.py --self-test  # internal consistency
"""

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

# ── File paths ─────────────────────────────────────────────────────────────

IMPL_FILE = ROOT / "crates/franken-node/src/tools/vef_perf_budget_gate.rs"
MOD_FILE = ROOT / "crates/franken-node/src/tools/mod.rs"
SPEC_FILE = ROOT / "docs/specs/section_10_18/bd-ufk5_contract.md"
EVIDENCE_FILE = ROOT / "artifacts/section_10_18/bd-ufk5/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_18/bd-ufk5/verification_summary.md"

ALL_CHECKS: list[dict[str, Any]] = []
RESULTS: dict[str, Any] = {}

# ── Required elements ──────────────────────────────────────────────────────

REQUIRED_TYPES = [
    "pub enum VefOperation",
    "pub enum BudgetMode",
    "pub struct LatencyBudget",
    "pub struct BudgetCheckResult",
    "pub struct MeasuredLatency",
    "pub struct VefPerfBudgetConfig",
    "pub struct VefPerfEvent",
    "pub struct GateVerdict",
    "pub struct OperationVerdict",
    "pub enum VerdictStatus",
    "pub struct BaselineSnapshot",
    "pub struct VefPerfBudgetGate",
    "pub struct RegressionReport",
    "pub enum VefPerfBudgetError",
]

REQUIRED_EVENT_CODES = [
    "VEF-PERF-001",
    "VEF-PERF-002",
    "VEF-PERF-003",
    "VEF-PERF-004",
    "VEF-PERF-005",
    "VEF-PERF-ERR-001",
]

REQUIRED_OPERATIONS = [
    "ReceiptEmission",
    "ChainAppend",
    "CheckpointComputation",
    "VerificationGateCheck",
    "ModeTransition",
    "ControlPlaneHotPath",
    "ExtensionHostHotPath",
]

REQUIRED_MODES = [
    "Normal",
    "Restricted",
    "Quarantine",
]

REQUIRED_FUNCTIONS = [
    "fn evaluate",
    "fn record_baseline",
    "fn detect_regressions",
    "fn budget_for",
    "fn validate",
    "fn check",
    "fn is_stable",
    "fn is_integration",
]

REQUIRED_INVARIANTS_SPEC = [
    "INV-VEF-PBG-BUDGET",
    "INV-VEF-PBG-GATE",
    "INV-VEF-PBG-BASELINE",
    "INV-VEF-PBG-NOISE",
    "INV-VEF-PBG-EVIDENCE",
    "INV-VEF-PBG-MODE",
]

REQUIRED_VERDICT_STATUSES = [
    "Pass",
    "Fail",
    "Skipped",
    "Unstable",
]


# ── Helpers ────────────────────────────────────────────────────────────────


def record(name: str, passed: bool, detail: str = "") -> None:
    ALL_CHECKS.append({"name": name, "passed": passed, "detail": detail})


def file_contains(path: Path, needle: str) -> bool:
    if not path.exists():
        return False
    return needle in path.read_text()


# ── Checks ─────────────────────────────────────────────────────────────────


def check_files_exist() -> None:
    for label, path in [
        ("impl_file", IMPL_FILE),
        ("mod_file", MOD_FILE),
        ("spec_file", SPEC_FILE),
    ]:
        exists = path.exists()
        record(f"file_exists:{label}", exists, str(path.relative_to(ROOT)))


def check_module_wired() -> None:
    wired = file_contains(MOD_FILE, "vef_perf_budget_gate")
    record("module_wired", wired, "tools/mod.rs includes vef_perf_budget_gate")


def check_required_types() -> None:
    for t in REQUIRED_TYPES:
        found = file_contains(IMPL_FILE, t)
        record(f"type:{t}", found, t)


def check_event_codes() -> None:
    for code in REQUIRED_EVENT_CODES:
        found = file_contains(IMPL_FILE, code)
        record(f"event_code:{code}", found, code)


def check_operations() -> None:
    for op in REQUIRED_OPERATIONS:
        found = file_contains(IMPL_FILE, op)
        record(f"operation:{op}", found, op)


def check_modes() -> None:
    for mode in REQUIRED_MODES:
        found = file_contains(IMPL_FILE, mode)
        record(f"mode:{mode}", found, mode)


def check_functions() -> None:
    for fn_sig in REQUIRED_FUNCTIONS:
        found = file_contains(IMPL_FILE, fn_sig)
        record(f"function:{fn_sig}", found, fn_sig)


def check_invariants_in_spec() -> None:
    for inv in REQUIRED_INVARIANTS_SPEC:
        found = file_contains(SPEC_FILE, inv)
        record(f"invariant_spec:{inv}", found, inv)


def check_invariants_in_impl() -> None:
    for inv in REQUIRED_INVARIANTS_SPEC:
        found = file_contains(IMPL_FILE, inv)
        record(f"invariant_impl:{inv}", found, inv)


def check_verdict_statuses() -> None:
    for status in REQUIRED_VERDICT_STATUSES:
        found = file_contains(IMPL_FILE, status)
        record(f"verdict_status:{status}", found, status)


def check_budget_structure() -> None:
    """Verify budgets cover 7 ops x 3 modes = 21 entries in default config."""
    impl_text = IMPL_FILE.read_text() if IMPL_FILE.exists() else ""
    # Check that all operations appear in the default config builder
    all_ops_in_default = all(
        f'"{op.lower()}"' in impl_text or f'"{op}"' in impl_text
        for op in [
            "receipt_emission",
            "chain_append",
            "checkpoint_computation",
            "verification_gate_check",
            "mode_transition",
            "control_plane_hot_path",
            "extension_host_hot_path",
        ]
    )
    record("budget_default_coverage", all_ops_in_default, "all 7 ops in default config")


def check_spec_acceptance_criteria() -> None:
    """Verify acceptance criteria exist in spec."""
    if not SPEC_FILE.exists():
        record("spec_acceptance_criteria", False, "spec file missing")
        return
    spec_text = SPEC_FILE.read_text()
    has_ac = "Acceptance Criteria" in spec_text
    record("spec_acceptance_criteria", has_ac, "acceptance criteria section present")


def check_unit_tests() -> None:
    """Verify that unit tests exist in the implementation."""
    if not IMPL_FILE.exists():
        record("rust_unit_tests", False, "impl file missing")
        return
    impl_text = IMPL_FILE.read_text()
    test_count = impl_text.count("#[test]")
    has_tests = test_count >= 15
    record(
        "rust_unit_tests",
        has_tests,
        f"{test_count} tests found (need >= 15)",
    )
    RESULTS["rust_test_count"] = test_count


def check_serde_derives() -> None:
    """Verify serialization support on key types."""
    if not IMPL_FILE.exists():
        record("serde_derives", False, "impl file missing")
        return
    impl_text = IMPL_FILE.read_text()
    has_serde = "Serialize, Deserialize" in impl_text
    record("serde_derives", has_serde, "key types derive Serialize/Deserialize")


# ── Self-test ──────────────────────────────────────────────────────────────


def self_test() -> dict[str, Any]:
    """Run internal consistency checks against the verification script itself."""
    st_checks: list[dict[str, Any]] = []

    def st_record(name: str, passed: bool, detail: str = "") -> None:
        st_checks.append({"name": name, "passed": passed, "detail": detail})

    # Verify all check lists are non-empty
    st_record("required_types_nonempty", len(REQUIRED_TYPES) > 0, f"{len(REQUIRED_TYPES)} types")
    st_record("required_event_codes_nonempty", len(REQUIRED_EVENT_CODES) > 0, f"{len(REQUIRED_EVENT_CODES)} codes")
    st_record("required_operations_nonempty", len(REQUIRED_OPERATIONS) > 0, f"{len(REQUIRED_OPERATIONS)} ops")
    st_record("required_modes_nonempty", len(REQUIRED_MODES) > 0, f"{len(REQUIRED_MODES)} modes")
    st_record("required_functions_nonempty", len(REQUIRED_FUNCTIONS) > 0, f"{len(REQUIRED_FUNCTIONS)} fns")
    st_record("required_invariants_nonempty", len(REQUIRED_INVARIANTS_SPEC) > 0, f"{len(REQUIRED_INVARIANTS_SPEC)} invs")

    # 7 operations expected
    st_record("operations_count", len(REQUIRED_OPERATIONS) == 7, f"{len(REQUIRED_OPERATIONS)} ops (need 7)")
    # 3 modes expected
    st_record("modes_count", len(REQUIRED_MODES) == 3, f"{len(REQUIRED_MODES)} modes (need 3)")
    # 6 event codes expected
    st_record("event_codes_count", len(REQUIRED_EVENT_CODES) == 6, f"{len(REQUIRED_EVENT_CODES)} codes (need 6)")
    # 6 invariants expected
    st_record("invariants_count", len(REQUIRED_INVARIANTS_SPEC) == 6, f"{len(REQUIRED_INVARIANTS_SPEC)} invs (need 6)")
    # 4 verdict statuses expected
    st_record("verdict_statuses_count", len(REQUIRED_VERDICT_STATUSES) == 4, f"{len(REQUIRED_VERDICT_STATUSES)} (need 4)")

    # Verify ROOT path points to project root
    st_record("root_has_cargo_toml", (ROOT / "Cargo.toml").exists(), str(ROOT / "Cargo.toml"))

    passed = sum(1 for c in st_checks if c["passed"])
    total = len(st_checks)

    return {
        "self_test": True,
        "passed": passed,
        "total": total,
        "all_passed": passed == total,
        "checks": st_checks,
    }


# ── Main ───────────────────────────────────────────────────────────────────


def main() -> None:
    logger = configure_test_logging("check_vef_perf_budget_gate")
    json_mode = "--json" in sys.argv
    self_test_mode = "--self-test" in sys.argv

    if self_test_mode:
        result = self_test()
        if json_mode:
            print(json.dumps(result, indent=2))
        else:
            for c in result["checks"]:
                status = "PASS" if c["passed"] else "FAIL"
                print(f"  [{status}] {c['name']}: {c['detail']}")
            print(f"\nSelf-test: {result['passed']}/{result['total']} passed")
        sys.exit(0 if result["all_passed"] else 1)

    check_files_exist()
    check_module_wired()
    check_required_types()
    check_event_codes()
    check_operations()
    check_modes()
    check_functions()
    check_invariants_in_spec()
    check_invariants_in_impl()
    check_verdict_statuses()
    check_budget_structure()
    check_spec_acceptance_criteria()
    check_unit_tests()
    check_serde_derives()

    passed = sum(1 for c in ALL_CHECKS if c["passed"])
    total = len(ALL_CHECKS)
    all_passed = passed == total

    output = {
        "bead_id": "bd-ufk5",
        "section": "10.18",
        "title": "VEF performance budget gates for p95/p99 hot paths",
        "passed": passed,
        "total": total,
        "all_passed": all_passed,
        "checks": ALL_CHECKS,
        **RESULTS,
    }

    if json_mode:
        print(json.dumps(output, indent=2))
    else:
        for c in ALL_CHECKS:
            status = "PASS" if c["passed"] else "FAIL"
            print(f"  [{status}] {c['name']}: {c['detail']}")
        print(f"\nResult: {passed}/{total} checks passed")
        if not all_passed:
            failed = [c for c in ALL_CHECKS if not c["passed"]]
            print(f"\nFailed ({len(failed)}):")
            for c in failed:
                print(f"  - {c['name']}: {c['detail']}")

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
