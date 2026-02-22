#!/usr/bin/env python3
"""bd-qlc6: Lane-aware scheduler verification gate.

Usage:
    python scripts/check_lane_scheduler.py          # human-readable
    python scripts/check_lane_scheduler.py --json    # machine-readable
"""
from __future__ import annotations

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "crates", "franken-node", "src", "runtime", "lane_scheduler.rs")
MOD = os.path.join(ROOT, "crates", "franken-node", "src", "runtime", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_10_14", "bd-qlc6_contract.md")

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
    src = read(SRC)
    mod_src = read(MOD)
    spec = read(SPEC)

    # --- Source existence ---
    check("source_exists", bool(src), SRC)

    # --- Module wiring ---
    check("mod_wired", "pub mod lane_scheduler;" in mod_src,
          "runtime/mod.rs must contain pub mod lane_scheduler")

    # --- SchedulerLane enum ---
    lanes = ["ControlCritical", "RemoteEffect", "Maintenance", "Background"]
    for lane in lanes:
        check(f"lane_{lane.lower()}", lane in src, f"SchedulerLane::{lane}")

    check("lane_count_4", "fn all()" in src and all(l in src for l in lanes),
          "SchedulerLane::all() with 4 lanes")

    # --- Task classes ---
    task_classes = [
        "epoch_transition", "barrier_coordination", "marker_write",
        "remote_computation", "artifact_upload", "artifact_eviction",
        "garbage_collection", "compaction", "telemetry_export", "log_rotation",
    ]
    for tc in task_classes:
        check(f"taskclass_{tc}", f'fn {tc}()' in src, f"task_classes::{tc}")

    # --- Key types ---
    types = [
        "SchedulerLane", "TaskClass", "LaneConfig", "MappingRule",
        "LaneMappingPolicy", "LaneCounters", "LaneSchedulerError",
        "TaskAssignment", "LaneAuditRecord", "LaneTelemetrySnapshot",
        "LaneScheduler",
    ]
    for t in types:
        check(f"type_{t}", f"pub struct {t}" in src or f"pub enum {t}" in src,
              f"type {t}")

    # --- Operations ---
    ops = [
        "assign_task", "complete_task", "check_starvation",
        "reload_policy", "telemetry_snapshot", "export_audit_log_jsonl",
    ]
    for op in ops:
        check(f"op_{op}", f"pub fn {op}" in src, f"operation {op}")

    # --- Event codes (10) ---
    event_codes = [
        "LANE_ASSIGN", "LANE_STARVED", "LANE_MISCLASS", "LANE_METRICS",
        "LANE_TASK_STARTED", "LANE_TASK_COMPLETED", "LANE_CAP_REACHED",
        "LANE_POLICY_RELOADED", "LANE_CREATED", "LANE_STARVATION_CLEARED",
    ]
    found_events = sum(1 for ec in event_codes if ec in src)
    check("event_codes_10", found_events == 10, f"{found_events}/10 event codes")

    # --- Error codes (8) ---
    error_codes = [
        "ERR_LANE_UNKNOWN_CLASS", "ERR_LANE_CAP_EXCEEDED",
        "ERR_LANE_UNKNOWN_LANE", "ERR_LANE_DUPLICATE",
        "ERR_LANE_INVALID_POLICY", "ERR_LANE_STARVATION",
        "ERR_LANE_TASK_NOT_FOUND", "ERR_LANE_INVALID_WEIGHT",
    ]
    found_errors = sum(1 for ec in error_codes if ec in src)
    check("error_codes_8", found_errors == 8, f"{found_errors}/8 error codes")

    # --- Invariant markers (6) ---
    invariants = [
        "INV-LANE-EXACT-MAP", "INV-LANE-STARVATION-DETECT",
        "INV-LANE-MISCLASS-REJECT", "INV-LANE-CAP-ENFORCE",
        "INV-LANE-TELEMETRY-ACCURATE", "INV-LANE-HOT-RELOAD",
    ]
    found_invs = sum(1 for inv in invariants if inv in src)
    check("invariants_6", found_invs == 6, f"{found_invs}/6 invariant markers")

    # --- Schema version ---
    check("schema_version", 'ls-v1.0' in src, "SCHEMA_VERSION = ls-v1.0")

    # --- Default policy ---
    check("default_policy", "pub fn default_policy()" in src,
          "default_policy() function")

    # --- JSONL export ---
    check("jsonl_export", "export_audit_log_jsonl" in src,
          "JSONL audit log export")

    # --- Starvation window ---
    check("starvation_window", "DEFAULT_STARVATION_WINDOW_MS" in src,
          "configurable starvation window")

    # --- Test coverage ---
    test_pattern = r"#\[test\]"
    test_count = len(re.findall(test_pattern, src))
    check("test_coverage", test_count >= 25,
          f"{test_count} inline tests (need >= 25)")

    # --- Spec contract ---
    check("spec_exists", bool(spec), SPEC)
    check("spec_mentions_lanes", "ControlCritical" in spec and "Background" in spec,
          "spec references scheduler lanes")

    # --- Serde derives ---
    check("serde_derives",
          "Serialize" in src and "Deserialize" in src,
          "Serde derives for serialization")

    # --- Policy validation ---
    check("policy_validation", "pub fn validate(" in src,
          "LaneMappingPolicy::validate()")

    return all(r["passed"] for r in results)


def self_test():
    """Verify the gate script itself."""
    ok = run_checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    print(f"self_test: {passed}/{total} checks passed")
    return ok


def main():
    ok = run_checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)

    if "--json" in sys.argv:
        print(json.dumps({
            "bead_id": "bd-qlc6",
            "section": "10.14",
            "gate": "lane_scheduler",
            "passed": passed,
            "total": total,
            "ok": ok,
            "checks": results,
        }, indent=2))
    else:
        for r in results:
            status = "PASS" if r["passed"] else "FAIL"
            detail = f" — {r['detail']}" if r["detail"] else ""
            print(f"  [{status}] {r['name']}{detail}")
        print(f"\n{'PASS' if ok else 'FAIL'}: {passed}/{total} checks passed")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
