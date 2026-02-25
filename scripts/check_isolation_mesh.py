#!/usr/bin/env python3
"""bd-gad3 verification gate for adaptive multi-rail isolation mesh."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path


BEAD = "bd-gad3"
SECTION = "10.17"

SPEC_FILE = ROOT / "docs/specs/section_10_17/bd-gad3_contract.md"
ARCH_FILE = ROOT / "docs/architecture/isolation_mesh.md"
IMPL_FILE = ROOT / "crates/franken-node/src/security/isolation_rail_router.rs"
SEC_MOD_FILE = ROOT / "crates/franken-node/src/security/mod.rs"
UNIT_TEST_FILE = ROOT / "tests/test_check_isolation_mesh.py"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-gad3/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-gad3/verification_summary.md"

REQUIRED_EVENT_CODES = [
    "ISOLATION_RAIL_ASSIGNED",
    "ISOLATION_ELEVATION_START",
    "ISOLATION_ELEVATION_COMPLETE",
    "ISOLATION_POLICY_PRESERVED",
    "ISOLATION_BUDGET_CHECK",
]

REQUIRED_ERROR_CODES = [
    "ERR_ISOLATION_RAIL_UNAVAILABLE",
    "ERR_ISOLATION_ELEVATION_DENIED",
    "ERR_ISOLATION_POLICY_BREAK",
    "ERR_ISOLATION_BUDGET_EXCEEDED",
    "ERR_ISOLATION_MESH_PARTITION",
    "ERR_ISOLATION_WORKLOAD_REJECTED",
]

REQUIRED_INVARIANTS = [
    "INV-ISOLATION-POLICY-CONTINUITY",
    "INV-ISOLATION-HOT-ELEVATION",
    "INV-ISOLATION-BUDGET-BOUND",
    "INV-ISOLATION-FAIL-SAFE",
]


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "passed": ok, "detail": detail or ("ok" if ok else "FAIL")}


def _checks() -> list[dict]:
    checks: list[dict] = []
    impl_src = _read(IMPL_FILE)
    spec_src = _read(SPEC_FILE) + _read(ARCH_FILE)
    sec_mod_src = _read(SEC_MOD_FILE)

    # -- file existence --
    checks.append(_check("Spec file exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("Implementation file exists", IMPL_FILE.exists(), str(IMPL_FILE)))
    checks.append(_check(
        "Security module wired",
        "pub mod isolation_rail_router;" in sec_mod_src,
        "pub mod isolation_rail_router; in security/mod.rs",
    ))

    # -- key types --
    required_types = [
        "struct RailRouter",
        "struct Placement",
        "struct Workload",
        "struct RailPolicy",
        "struct PolicyRule",
        "struct MeshConfig",
        "enum IsolationRail",
        "enum TrustProfile",
        "enum RailRouterError",
    ]
    for token in required_types:
        checks.append(_check(f"Type '{token}'", token in impl_src, token))

    # -- key functions --
    required_fns = [
        "fn assign_workload",
        "fn hot_elevate",
        "fn record_latency",
        "fn check_mesh_connectivity",
        "fn mesh_profile_report",
        "fn is_subset_of",
        "fn can_elevate_to",
        "fn is_downgrade_to",
        "fn remove_workload",
    ]
    for token in required_fns:
        checks.append(_check(f"Fn '{token}'", token in impl_src, token))

    # -- isolation levels --
    required_levels = ["Standard", "Elevated", "HighAssurance", "Critical"]
    for level in required_levels:
        checks.append(_check(f"IsolationRail::{level}", level in impl_src, level))

    # -- event codes in impl --
    for code in REQUIRED_EVENT_CODES:
        checks.append(_check(f"Event code {code}", code in impl_src, code))

    # -- error codes in impl --
    for code in REQUIRED_ERROR_CODES:
        checks.append(_check(f"Error code {code}", code in impl_src, code))

    # -- invariants in impl --
    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(f"Invariant {inv}", inv in impl_src, inv))

    # -- Rust unit test count --
    test_count = impl_src.count("#[test]")
    checks.append(_check("Rust unit tests >= 25", test_count >= 25, f"found {test_count}"))

    # -- Python checker unit test exists --
    checks.append(_check(
        "Python checker unit test exists",
        UNIT_TEST_FILE.exists(),
        str(UNIT_TEST_FILE),
    ))

    # -- Evidence and summary --
    checks.append(_check("Evidence file exists", EVIDENCE_FILE.exists(), str(EVIDENCE_FILE)))
    checks.append(_check("Summary file exists", SUMMARY_FILE.exists(), str(SUMMARY_FILE)))

    return checks


def run_all() -> dict:
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "schema_version": "isolation-mesh-v1.0",
        "bead_id": BEAD,
        "section": SECTION,
        "title": "Adaptive multi-rail isolation mesh with hot-elevation policy",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "event_codes": REQUIRED_EVENT_CODES,
        "error_codes": REQUIRED_ERROR_CODES,
        "invariants": REQUIRED_INVARIANTS,
        "mesh_contract": {
            "monotonic_elevation_only": True,
            "demotion_forbidden": True,
            "policy_continuity_preserved": True,
            "latency_budget_enforced": True,
            "deterministic_topology": True,
            "fail_closed_on_unknown": True,
        },
    }


def self_test() -> dict:
    checks: list[dict] = []
    checks.append(_check("event code count >= 5", len(REQUIRED_EVENT_CODES) >= 5))
    checks.append(_check("error code count >= 6", len(REQUIRED_ERROR_CODES) >= 6))
    checks.append(_check("invariant count >= 4", len(REQUIRED_INVARIANTS) >= 4))

    result = run_all()
    checks.append(_check("run_all has verdict", result.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_all has checks", isinstance(result.get("checks"), list)))
    checks.append(_check("run_all checks non-empty", len(result.get("checks", [])) > 10))

    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "name": "check_isolation_mesh",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": verdict,
    }


def main() -> None:
    logger = configure_test_logging("check_isolation_mesh")
    parser = argparse.ArgumentParser(description="bd-gad3 checker")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        st = self_test()
        if args.json:
            print(json.dumps(st, indent=2))
        else:
            print(f"self-test: {st['verdict']} ({st['passed']}/{st['passed'] + st['failed']})")
        sys.exit(0 if st["verdict"] == "PASS" else 1)

    result = run_all()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{BEAD}: {result['verdict']} ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "+" if c["passed"] else "x"
            print(f"[{mark}] {c['check']}: {c['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
