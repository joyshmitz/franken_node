#!/usr/bin/env python3
"""bd-1cs7: Three-phase cancellation protocol (REQUEST -> DRAIN -> FINALIZE) -- verification gate.

Usage:
    python scripts/check_cancellation_protocol.py            # human-readable
    python scripts/check_cancellation_protocol.py --json     # machine-readable JSON
    python scripts/check_cancellation_protocol.py --self-test # self-test mode
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SRC = ROOT / "crates" / "franken-node" / "src" / "connector" / "cancellation_protocol.rs"
MOD = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_15" / "bd-1cs7_contract.md"
TIMING_CSV = ROOT / "artifacts" / "10.15" / "cancel_protocol_timing.csv"

BEAD = "bd-1cs7"
SECTION = "10.15"

PHASES = [
    "Idle", "Requested", "Draining", "Finalizing", "Completed",
]

EVENT_CODES = [
    "CAN-001", "CAN-002", "CAN-003", "CAN-004", "CAN-005", "CAN-006",
]

INVARIANTS = [
    "INV-CAN-THREE-PHASE",
    "INV-CAN-BUDGET-BOUNDED",
    "INV-CAN-PROPAGATION",
    "INV-CAN-NO-LEAK",
]

ERROR_CODES = [
    "ERR_CANCEL_INVALID_PHASE",
    "ERR_CANCEL_ALREADY_FINAL",
    "ERR_CANCEL_DRAIN_TIMEOUT",
    "ERR_CANCEL_LEAK",
]

TYPES = [
    "CancellationPhase", "CancellationBudget", "CancellationProtocol",
    "ResourceGuard", "ResourceTracker", "CancellationAuditEvent",
    "PhaseTransitionResult", "WorkflowKind", "TimingRow",
]

OPS = [
    "fn request", "fn drain", "fn finalize", "fn run_full",
    "fn force_finalize", "fn register_child", "fn complete_child",
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


def check_files() -> list:
    checks = []
    checks.append(_check("file: source module", SRC.exists(), _safe_rel(SRC)))
    checks.append(_check("file: spec contract", SPEC.exists(), _safe_rel(SPEC)))
    checks.append(_check("file: timing CSV", TIMING_CSV.exists(), _safe_rel(TIMING_CSV)))
    return checks


def check_module_wired() -> list:
    mod_src = _read(MOD)
    return [_check(
        "module wired in connector/mod.rs",
        "pub mod cancellation_protocol;" in mod_src,
        "connector/mod.rs contains pub mod cancellation_protocol"
    )]


def check_phases() -> list:
    src = _read(SRC)
    checks = []
    for phase in PHASES:
        checks.append(_check(f"phase: {phase}", phase in src))
    return checks


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
        checks.append(_check(f"op: {op}", op in src))
    return checks


def check_event_codes() -> list:
    src = _read(SRC)
    found = sum(1 for ec in EVENT_CODES if ec in src)
    return [_check(f"event codes ({found}/{len(EVENT_CODES)})", found == len(EVENT_CODES), f"{found}/{len(EVENT_CODES)}")]


def check_invariants() -> list:
    src = _read(SRC)
    found = sum(1 for inv in INVARIANTS if inv in src)
    return [_check(f"invariants ({found}/{len(INVARIANTS)})", found == len(INVARIANTS), f"{found}/{len(INVARIANTS)}")]


def check_error_codes() -> list:
    src = _read(SRC)
    found = sum(1 for ec in ERROR_CODES if ec in src)
    return [_check(f"error codes ({found}/{len(ERROR_CODES)})", found == len(ERROR_CODES), f"{found}/{len(ERROR_CODES)}")]


def check_schema_version() -> list:
    src = _read(SRC)
    return [_check("schema version cancel-v1.0", "cancel-v1.0" in src)]


def check_serde() -> list:
    src = _read(SRC)
    return [_check("Serialize/Deserialize derives",
                   "Serialize" in src and "Deserialize" in src)]


def check_resource_guard_drop() -> list:
    src = _read(SRC)
    return [_check("ResourceGuard Drop impl", "impl Drop for ResourceGuard" in src)]


def check_test_count() -> list:
    src = _read(SRC)
    count = len(re.findall(r"#\[test\]", src))
    return [_check(f"inline tests >= 15", count >= 15, f"{count} tests")]


def check_timing_csv_columns() -> list:
    content = _read(TIMING_CSV)
    if not content:
        return [_check("timing CSV columns", False, "file missing")]
    header = content.splitlines()[0] if content.splitlines() else ""
    expected_cols = ["workflow_id", "phase", "budget_ms", "actual_ms", "within_budget", "resources_released"]
    all_present = all(col in header for col in expected_cols)
    return [_check("timing CSV columns", all_present, header)]


def check_timing_csv_rows() -> list:
    content = _read(TIMING_CSV)
    if not content:
        return [_check("timing CSV rows >= 6", False, "file missing")]
    lines = [l.strip() for l in content.strip().splitlines() if l.strip()]
    data_rows = len(lines) - 1  # exclude header
    return [_check(f"timing CSV rows >= 6", data_rows >= 6, f"{data_rows} data rows")]


def check_spec_sections() -> list:
    content = _read(SPEC)
    if not content:
        return [_check("spec sections", False, "spec missing")]
    checks = []
    for section in ["Invariants", "Event Codes", "Error Codes", "Acceptance Criteria",
                    "Three-Phase Protocol", "Per-Workflow Cleanup Budgets", "Gate Behavior"]:
        checks.append(_check(f"spec: {section}", section in content))
    return checks


def run_checks() -> dict:
    checks = []
    checks.extend(check_files())
    checks.extend(check_module_wired())
    checks.extend(check_phases())
    checks.extend(check_types())
    checks.extend(check_ops())
    checks.extend(check_event_codes())
    checks.extend(check_invariants())
    checks.extend(check_error_codes())
    checks.extend(check_schema_version())
    checks.extend(check_serde())
    checks.extend(check_resource_guard_drop())
    checks.extend(check_test_count())
    checks.extend(check_timing_csv_columns())
    checks.extend(check_timing_csv_rows())
    checks.extend(check_spec_sections())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])
    verdict = "PASS" if failing == 0 else "FAIL"

    return {
        "bead_id": BEAD,
        "title": "Three-phase cancellation protocol (REQUEST -> DRAIN -> FINALIZE)",
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


def self_test() -> tuple:
    result = run_checks()
    if not result["overall_pass"]:
        failures = [c for c in result["checks"] if not c["pass"]]
        detail = "; ".join(f"{c['check']}: {c['detail']}" for c in failures[:5])
        return False, f"self_test failed: {detail}"
    return True, "self_test passed"


def main():
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
    print(f"\n{BEAD} verification: {result['verdict']} ({passing}/{total} checks pass)")
    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
