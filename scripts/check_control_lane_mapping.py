#!/usr/bin/env python3
"""bd-cuut: Control-plane lane mapping policy verification gate.

Checks the Rust implementation of the control-plane lane mapping policy
(Cancel/Timed/Ready lanes) including types, operations, event codes,
error codes, invariants, budget allocation, and task class assignments.

Usage:
    python scripts/check_control_lane_mapping.py            # human-readable
    python scripts/check_control_lane_mapping.py --json     # machine-readable JSON
    python scripts/check_control_lane_mapping.py --self-test # self-test mode
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path


# ---- Paths ----
SRC = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "control_lane_mapping.rs"
MOD = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_15" / "bd-cuut_contract.md"

# ---- Expected types ----
TYPES = [
    "ControlLane", "ControlTaskClass", "LaneBudget",
    "ControlLanePolicy", "LaneTickCounters", "StarvationMetrics",
    "ControlLanePolicyError", "ControlLaneAuditRecord", "ControlLaneScheduler",
]

# ---- Expected operations ----
OPS = [
    "assign", "set_budget", "resolve", "validate",
    "default_control_lane_policy", "assign_task", "advance_tick",
    "starvation_metrics", "starvation_metrics_csv_row",
    "export_audit_log_jsonl", "select_next_lane", "set_queued",
]

# ---- Lanes ----
LANES = ["Cancel", "Timed", "Ready"]

# ---- Cancel lane tasks ----
CANCEL_TASKS = ["cancellation_handler", "drain_operation", "region_close", "shutdown_handler"]
# ---- Timed lane tasks ----
TIMED_TASKS = ["health_check", "lease_renewal", "epoch_transition", "barrier_coordination", "marker_append"]
# ---- Ready lane tasks ----
READY_TASKS = ["telemetry_flush", "evidence_archival", "compaction", "garbage_collection", "log_rotation"]
ALL_TASKS = CANCEL_TASKS + TIMED_TASKS + READY_TASKS

# ---- Event codes ----
EVENT_CODES = [
    "CLM_TASK_ASSIGNED", "CLM_STARVATION_ALERT", "CLM_BUDGET_VIOLATION",
    "CLM_POLICY_LOADED", "CLM_PRIORITY_OVERRIDE", "CLM_TICK_COMPLETE",
    "CLM_METRICS_EXPORTED", "CLM_STARVATION_CLEARED",
]

# ---- Error codes ----
ERROR_CODES = [
    "ERR_CLM_UNKNOWN_TASK", "ERR_CLM_BUDGET_OVERFLOW", "ERR_CLM_STARVATION",
    "ERR_CLM_INVALID_BUDGET", "ERR_CLM_DUPLICATE_TASK", "ERR_CLM_INCOMPLETE_MAP",
]

# ---- Invariants ----
INVARIANTS = [
    "INV-CLM-COMPLETE-MAP", "INV-CLM-BUDGET-SUM", "INV-CLM-CANCEL-PRIORITY",
    "INV-CLM-STARVATION-DETECT", "INV-CLM-CANCEL-MIN-BUDGET", "INV-CLM-TIMED-MIN-BUDGET",
]


def _safe_rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def _check(name: str, passed: bool, detail: str = "") -> dict:
    return {"check": name, "pass": passed, "detail": detail or ("found" if passed else "missing")}


def _read(p: Path) -> str:
    if not p.exists():
        return ""
    return p.read_text()


# ==========================================================================
# Section A: File existence and module wiring
# ==========================================================================

def check_files() -> list:
    checks = []
    checks.append(_check("file: source module", SRC.exists(), _safe_rel(SRC)))
    checks.append(_check("file: spec contract", SPEC.exists(), _safe_rel(SPEC)))
    return checks


def check_module_wired() -> list:
    mod_src = _read(MOD)
    return [_check(
        "module wired in control_plane/mod.rs",
        "pub mod control_lane_mapping;" in mod_src,
        "control_plane/mod.rs contains pub mod control_lane_mapping"
    )]


# ==========================================================================
# Section B: Types and operations
# ==========================================================================

def check_types() -> list:
    src = _read(SRC)
    checks = []
    for t in TYPES:
        found = f"pub struct {t}" in src or f"pub enum {t}" in src
        checks.append(_check(f"type: {t}", found))
    return checks


def check_ops() -> list:
    src = _read(SRC)
    checks = []
    for op in OPS:
        checks.append(_check(f"op: {op}", f"pub fn {op}" in src or f"fn {op}" in src))
    return checks


# ==========================================================================
# Section C: Lanes and task classes
# ==========================================================================

def check_lanes() -> list:
    src = _read(SRC)
    checks = []
    for lane in LANES:
        checks.append(_check(f"lane: {lane}", lane in src))
    return checks


def check_task_classes() -> list:
    src = _read(SRC)
    checks = []
    for task in ALL_TASKS:
        checks.append(_check(f"task_class: {task}", f'"{task}"' in src))
    return checks


def check_cancel_lane_tasks() -> list:
    src = _read(SRC)
    for task in CANCEL_TASKS:
        if "ControlLane::Cancel" not in src:
            return [_check("cancel lane assignments", False, "ControlLane::Cancel not found")]
    return [_check("cancel lane assignments", True, f"{len(CANCEL_TASKS)} tasks")]


def check_timed_lane_tasks() -> list:
    src = _read(SRC)
    if "ControlLane::Timed" not in src:
        return [_check("timed lane assignments", False, "ControlLane::Timed not found")]
    return [_check("timed lane assignments", True, f"{len(TIMED_TASKS)} tasks")]


def check_ready_lane_tasks() -> list:
    src = _read(SRC)
    if "ControlLane::Ready" not in src:
        return [_check("ready lane assignments", False, "ControlLane::Ready not found")]
    return [_check("ready lane assignments", True, f"{len(READY_TASKS)} tasks")]


# ==========================================================================
# Section D: Event codes, error codes, invariants
# ==========================================================================

def check_event_codes() -> list:
    src = _read(SRC)
    found = sum(1 for ec in EVENT_CODES if ec in src)
    return [_check(f"event codes ({found}/{len(EVENT_CODES)})", found == len(EVENT_CODES), f"{found}/{len(EVENT_CODES)}")]


def check_error_codes() -> list:
    src = _read(SRC)
    found = sum(1 for ec in ERROR_CODES if ec in src)
    return [_check(f"error codes ({found}/{len(ERROR_CODES)})", found == len(ERROR_CODES), f"{found}/{len(ERROR_CODES)}")]


def check_invariants() -> list:
    src = _read(SRC)
    found = sum(1 for inv in INVARIANTS if inv in src)
    return [_check(f"invariants ({found}/{len(INVARIANTS)})", found == len(INVARIANTS), f"{found}/{len(INVARIANTS)}")]


# ==========================================================================
# Section E: Budget and schema
# ==========================================================================

def check_budget_defaults() -> list:
    src = _read(SRC)
    checks = []
    checks.append(_check("cancel budget >= 20%", "min_percent: 20" in src))
    checks.append(_check("timed budget >= 30%", "min_percent: 30" in src))
    checks.append(_check("ready budget 50%", "min_percent: 50" in src))
    return checks


def check_schema_version() -> list:
    src = _read(SRC)
    return [_check("schema version clm-v1.0", "clm-v1.0" in src)]


def check_serde() -> list:
    src = _read(SRC)
    return [_check("Serialize/Deserialize derives",
                   "Serialize" in src and "Deserialize" in src)]


def check_test_count() -> list:
    src = _read(SRC)
    count = len(re.findall(r"#\[test\]", src))
    return [_check("inline tests >= 25", count >= 25, f"{count} tests")]


# ==========================================================================
# Section F: Spec contract
# ==========================================================================

def check_spec_sections() -> list:
    content = _read(SPEC)
    if not content:
        return [_check("spec sections", False, "spec missing")]
    checks = []
    for section in ["Cancel", "Timed", "Ready", "Invariants", "Event Codes",
                    "Error Codes", "Acceptance Criteria"]:
        checks.append(_check(f"spec: {section}", section in content))
    return checks


# ==========================================================================
# Main
# ==========================================================================

def run_checks() -> dict:
    checks = []

    # A: Files and wiring
    checks.extend(check_files())
    checks.extend(check_module_wired())

    # B: Types and operations
    checks.extend(check_types())
    checks.extend(check_ops())

    # C: Lanes and task classes
    checks.extend(check_lanes())
    checks.extend(check_task_classes())
    checks.extend(check_cancel_lane_tasks())
    checks.extend(check_timed_lane_tasks())
    checks.extend(check_ready_lane_tasks())

    # D: Event codes, error codes, invariants
    checks.extend(check_event_codes())
    checks.extend(check_error_codes())
    checks.extend(check_invariants())

    # E: Budget and schema
    checks.extend(check_budget_defaults())
    checks.extend(check_schema_version())
    checks.extend(check_serde())
    checks.extend(check_test_count())

    # F: Spec
    checks.extend(check_spec_sections())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])
    verdict = "PASS" if failing == 0 else "FAIL"

    return {
        "bead_id": "bd-cuut",
        "title": "Control-plane lane mapping policy",
        "section": "10.15",
        "overall_pass": failing == 0,
        "verdict": verdict,
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": passing + failing,
        },
        "checks": checks,
    }


def self_test() -> tuple:
    result = run_checks()
    if not result["overall_pass"]:
        failures = [c for c in result["checks"] if not c["pass"]]
        detail = "; ".join(f"{c['check']}: {c['detail']}" for c in failures[:5])
        return False, f"self_test failed: {detail}"
    return True, "self_test passed"


def main():
    logger = configure_test_logging("check_control_lane_mapping")
    if "--self-test" in sys.argv:
        ok, msg = self_test()
        print(msg)
        sys.exit(0 if ok else 1)

    result = run_checks()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["overall_pass"] else 1)

    for c in result["checks"]:
        status = "PASS" if c["pass"] else "FAIL"
        print(f"  [{status}] {c['check']}: {c['detail']}")

    passing = result["summary"]["passing"]
    total = result["summary"]["total"]
    print(f"\nbd-cuut verification: {result['verdict']} ({passing}/{total} checks pass)")
    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
