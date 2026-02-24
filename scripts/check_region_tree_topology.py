#!/usr/bin/env python3
"""bd-2tdi: Region-owned execution tree topology verification gate.

Usage:
    python scripts/check_region_tree_topology.py              # human-readable
    python scripts/check_region_tree_topology.py --json        # machine-readable
    python scripts/check_region_tree_topology.py --self-test   # self-validation
"""
from __future__ import annotations

import json
import os
import re
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "crates", "franken-node", "src", "runtime", "region_tree.rs")
MOD = os.path.join(ROOT, "crates", "franken-node", "src", "runtime", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_10_15", "bd-2tdi_contract.md")
TRACE = os.path.join(ROOT, "artifacts", "10.15", "region_quiescence_trace.jsonl")

results: list[dict] = []


def check(name: str, passed: bool, detail: str = "") -> bool:
    results.append({"name": name, "passed": passed, "detail": detail})
    return passed


def read(path: str) -> str:
    try:
        with open(path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def run_checks() -> bool:
    global results
    results = []

    src = read(SRC)
    mod_src = read(MOD)
    spec = read(SPEC)
    trace = read(TRACE)

    # --- Source existence ---
    check("source_exists", bool(src), SRC)

    # --- Module wiring ---
    check("mod_wired", "pub mod region_tree;" in mod_src,
          "runtime/mod.rs must contain pub mod region_tree")

    # --- Spec contract ---
    check("spec_exists", bool(spec), SPEC)
    check("spec_mentions_hierarchy",
          "health-gate" in spec and "rollout" in spec and "fencing" in spec,
          "spec references region hierarchy")
    check("spec_schema_version", "region-v1.0" in spec,
          "spec has schema_version region-v1.0")

    # --- Core types ---
    types = ["RegionId", "RegionState", "RegionTree", "RegionHandle"]
    for t in types:
        check(f"type_{t}",
              f"pub struct {t}" in src or f"pub enum {t}" in src,
              f"type {t}")

    # --- RegionState variants ---
    for variant in ["Active", "Draining", "Closed"]:
        check(f"state_{variant.lower()}", variant in src,
              f"RegionState::{variant}")

    # --- Core operations ---
    ops = ["open_region", "register_task", "close", "force_terminate"]
    for op in ops:
        check(f"op_{op}", f"pub fn {op}" in src, f"operation {op}")

    # --- Invariant constants (3) ---
    invariants = [
        "INV-REGION-QUIESCENCE",
        "INV-REGION-NO-OUTLIVE",
        "INV-REGION-DETERMINISTIC-CLOSE",
    ]
    found_invs = sum(1 for inv in invariants if inv in src)
    check("invariants_3", found_invs == 3, f"{found_invs}/3 invariant constants")

    # --- Event code constants (8): REG-001 through REG-008 ---
    event_codes = [
        "REG-001", "REG-002", "REG-003", "REG-004",
        "REG-005", "REG-006", "REG-007", "REG-008",
    ]
    found_events = sum(1 for ec in event_codes if ec in src)
    check("event_codes_8", found_events == 8, f"{found_events}/8 event codes")

    # --- Error codes ---
    error_codes = [
        "ERR_REGION_NOT_FOUND",
        "ERR_REGION_ALREADY_CLOSED",
        "ERR_REGION_PARENT_NOT_FOUND",
        "ERR_REGION_BUDGET_EXCEEDED",
    ]
    found_errors = sum(1 for ec in error_codes if ec in src)
    check("error_codes_4", found_errors == 4, f"{found_errors}/4 error codes")

    # --- Quiescence trace artifact ---
    check("trace_exists", bool(trace), TRACE)
    if trace:
        lines = [l for l in trace.strip().splitlines() if l.strip()]
        valid_jsonl = True
        for line in lines:
            try:
                obj = json.loads(line)
                if "region_id" not in obj or "action" not in obj:
                    valid_jsonl = False
                    break
            except json.JSONDecodeError:
                valid_jsonl = False
                break
        check("trace_valid_jsonl", valid_jsonl,
              f"{len(lines)} lines, all valid JSONL with region_id and action")
        # Check trace has open/close/drain events
        actions = set()
        for line in lines:
            obj = json.loads(line)
            actions.add(obj.get("action", ""))
        check("trace_has_lifecycle_actions",
              "open" in actions and "close" in actions and "drain" in actions,
              f"actions found: {sorted(actions)}")
    else:
        check("trace_valid_jsonl", False, "trace file missing")
        check("trace_has_lifecycle_actions", False, "trace file missing")

    # --- Unit tests present ---
    test_pattern = r"#\[test\]"
    test_count = len(re.findall(test_pattern, src))
    check("unit_tests_present", test_count >= 10,
          f"{test_count} inline tests (need >= 10)")

    # --- Serde derives ---
    check("serde_derives",
          "Serialize" in src and "Deserialize" in src,
          "Serde derives for serialization")

    # --- Schema version ---
    check("schema_version", "region-v1.0" in src,
          "SCHEMA_VERSION = region-v1.0")

    # --- JSONL export ---
    check("jsonl_export", "export_event_log_jsonl" in src,
          "JSONL event log export")

    return all(r["passed"] for r in results)


def self_test() -> bool:
    """Verify the gate script itself."""
    ok = run_checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    print(f"self_test: {passed}/{total} checks passed")
    return ok


def main():
    logger = configure_test_logging("check_region_tree_topology")
    if "--self-test" in sys.argv:
        ok = self_test()
        sys.exit(0 if ok else 1)

    ok = run_checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)

    if "--json" in sys.argv:
        print(json.dumps({
            "bead_id": "bd-2tdi",
            "section": "10.15",
            "gate": "region_tree_topology",
            "passed": passed,
            "total": total,
            "verdict": "PASS" if ok else "FAIL",
            "ok": ok,
            "checks": results,
            "events": [
                "REG-001", "REG-002", "REG-003", "REG-004",
                "REG-005", "REG-006", "REG-007", "REG-008",
            ],
        }, indent=2))
    else:
        for r in results:
            status = "PASS" if r["passed"] else "FAIL"
            detail = f" -- {r['detail']}" if r["detail"] else ""
            print(f"  [{status}] {r['name']}{detail}")
        print(f"\n{'PASS' if ok else 'FAIL'}: {passed}/{total} checks passed")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
