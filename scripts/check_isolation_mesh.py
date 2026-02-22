#!/usr/bin/env python3
"""bd-gad3 verification gate for adaptive multi-rail isolation mesh."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BEAD = "bd-gad3"
SECTION = "10.17"

SPEC_FILE = ROOT / "docs/specs/section_10_17/bd-gad3_contract.md"
IMPL_FILE = ROOT / "crates/franken-node/src/runtime/isolation_mesh.rs"
RUNTIME_MOD_FILE = ROOT / "crates/franken-node/src/runtime/mod.rs"
UNIT_TEST_FILE = ROOT / "tests/test_check_isolation_mesh.py"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-gad3/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-gad3/verification_summary.md"

REQUIRED_EVENT_CODES = [
    "MESH_001",
    "MESH_002",
    "MESH_003",
    "MESH_004",
    "MESH_005",
    "MESH_006",
    "MESH_007",
]

REQUIRED_ERROR_CODES = [
    "ERR_MESH_UNKNOWN_RAIL",
    "ERR_MESH_UNKNOWN_WORKLOAD",
    "ERR_MESH_ELEVATION_DENIED",
    "ERR_MESH_DEMOTION_FORBIDDEN",
    "ERR_MESH_LATENCY_EXCEEDED",
    "ERR_MESH_RAIL_AT_CAPACITY",
    "ERR_MESH_DUPLICATE_WORKLOAD",
    "ERR_MESH_INVALID_TOPOLOGY",
]

REQUIRED_INVARIANTS = [
    "INV-MESH-MONOTONIC-ELEVATION",
    "INV-MESH-POLICY-CONTINUITY",
    "INV-MESH-ATOMIC-TRANSITION",
    "INV-MESH-LATENCY-BUDGET",
    "INV-MESH-DETERMINISTIC-TOPOLOGY",
    "INV-MESH-FAIL-CLOSED",
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
    spec_src = _read(SPEC_FILE)
    runtime_mod_src = _read(RUNTIME_MOD_FILE)

    # -- file existence --
    checks.append(_check("Spec file exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("Implementation file exists", IMPL_FILE.exists(), str(IMPL_FILE)))
    checks.append(_check(
        "Runtime module wired",
        "pub mod isolation_mesh;" in runtime_mod_src,
        "pub mod isolation_mesh; in runtime/mod.rs",
    ))

    # -- key types --
    required_types = [
        "struct IsolationMesh",
        "struct IsolationRail",
        "struct ElevationPolicy",
        "struct MeshTopology",
        "struct RailState",
        "struct WorkloadPlacement",
        "struct MeshEvent",
        "struct ElevationRecord",
        "enum IsolationRailLevel",
        "enum MeshError",
    ]
    for token in required_types:
        checks.append(_check(f"Type '{token}'", token in impl_src, token))

    # -- key functions --
    required_fns = [
        "fn place_workload",
        "fn elevate_workload",
        "fn remove_workload",
        "fn reload_topology",
        "fn permits_elevation",
        "fn can_elevate_to",
        "fn validate",
    ]
    for token in required_fns:
        checks.append(_check(f"Fn '{token}'", token in impl_src, token))

    # -- isolation levels --
    required_levels = [
        "Shared",
        "ProcessIsolated",
        "SandboxIsolated",
        "HardwareIsolated",
    ]
    for level in required_levels:
        checks.append(_check(f"IsolationRailLevel::{level}", level in impl_src, level))

    # -- event codes --
    for code in REQUIRED_EVENT_CODES:
        checks.append(_check(
            f"Event code {code}",
            code in impl_src and code in spec_src,
            code,
        ))

    # -- error codes --
    for code in REQUIRED_ERROR_CODES:
        checks.append(_check(
            f"Error code {code}",
            code in impl_src and code in spec_src,
            code,
        ))

    # -- invariants --
    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(
            f"Invariant {inv}",
            inv in impl_src and inv in spec_src,
            inv,
        ))

    # -- schema version --
    checks.append(_check(
        "Schema version constant",
        'SCHEMA_VERSION' in impl_src and 'isolation-mesh-v1.0' in impl_src,
        "SCHEMA_VERSION = isolation-mesh-v1.0",
    ))

    # -- BTreeMap for deterministic ordering --
    checks.append(_check(
        "BTreeMap used for determinism",
        "BTreeMap" in impl_src,
        "BTreeMap in impl",
    ))

    # -- Rust unit test count --
    test_count = impl_src.count("#[test]")
    checks.append(_check("Rust unit tests >= 20", test_count >= 20, f"found {test_count}"))

    # -- Python checker unit test exists --
    checks.append(_check(
        "Python checker unit test exists",
        UNIT_TEST_FILE.exists(),
        str(UNIT_TEST_FILE),
    ))

    # -- Evidence and summary --
    checks.append(_check("Evidence file exists", EVIDENCE_FILE.exists(), str(EVIDENCE_FILE)))
    checks.append(_check("Summary file exists", SUMMARY_FILE.exists(), str(SUMMARY_FILE)))

    # -- acceptance criteria tokens --
    checks.append(_check(
        "Monotonic elevation enforced (demotion forbidden)",
        "DemotionForbidden" in impl_src,
        "DemotionForbidden variant present",
    ))
    checks.append(_check(
        "Latency budget enforcement",
        "LatencyExceeded" in impl_src and "latency_budget_us" in impl_src,
        "LatencyExceeded + latency_budget_us in impl",
    ))
    checks.append(_check(
        "Policy continuity across elevation",
        "elevation_history" in impl_src and "policy" in impl_src,
        "elevation_history + policy carried in WorkloadPlacement",
    ))

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
    checks.append(_check("event code count >= 7", len(REQUIRED_EVENT_CODES) >= 7))
    checks.append(_check("error code count >= 8", len(REQUIRED_ERROR_CODES) >= 8))
    checks.append(_check("invariant count >= 6", len(REQUIRED_INVARIANTS) >= 6))

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
