#!/usr/bin/env python3
"""bd-3tpg: Cancel injection gate verification for control-plane workflows.

Usage:
    python scripts/check_cancel_injection_gate.py            # human-readable
    python scripts/check_cancel_injection_gate.py --json     # machine-readable JSON
    python scripts/check_cancel_injection_gate.py --self-test # self-test mode
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


SRC = ROOT / "crates" / "franken-node" / "src" / "connector" / "cancel_injection_gate.rs"
MOD = ROOT / "crates" / "franken-node" / "src" / "connector" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_15" / "bd-3tpg_contract.md"
UPSTREAM = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "cancellation_injection.rs"

TYPES = [
    "ControlWorkflow", "WorkflowInjectionResult", "PointFailure",
    "CancelInjectionGateReport", "GateAuditRecord", "CancelInjectionGate",
]

OPS = [
    "register_control_workflow", "register_default_control_workflows",
    "run_injection_case", "run_full_gate", "framework",
    "export_audit_log_jsonl", "export_report_json", "control_workflow_count",
]

CONTROL_WORKFLOWS = [
    "connector_lifecycle", "rollout_transition", "quarantine_promotion",
    "migration_orchestration", "fencing_acquire", "health_gate_evaluation",
]

EVENT_CODES = [
    "CIN-001", "CIN-002", "CIN-003", "CIN-004",
    "CIN-005", "CIN-006", "CIN-007", "CIN-008",
]

ERROR_CODES = [
    "ERR_CIG_LEAK_DETECTED", "ERR_CIG_HALFCOMMIT", "ERR_CIG_QUIESCENCE",
    "ERR_CIG_MATRIX_INCOMPLETE", "ERR_CIG_CUSTOM_INJECTION", "ERR_CIG_MISSING_WORKFLOW",
]

INVARIANTS = [
    "INV-CIG-CANONICAL-ONLY", "INV-CIG-ALL-WORKFLOWS", "INV-CIG-FULL-MATRIX",
    "INV-CIG-ZERO-FAILURES", "INV-CIG-LEAK-FREE", "INV-CIG-REPORT-COMPLETE",
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
    checks.append(_check("file: upstream framework", UPSTREAM.exists(), _safe_rel(UPSTREAM)))
    return checks


def check_module_wired() -> list:
    mod_src = _read(MOD)
    return [_check(
        "module wired in connector/mod.rs",
        "pub mod cancel_injection_gate;" in mod_src,
        "connector/mod.rs contains pub mod cancel_injection_gate"
    )]


def check_canonical_import() -> list:
    src = _read(SRC)
    return [_check(
        "imports canonical framework (bd-876n)",
        "cancellation_injection" in src and "CancellationInjectionFramework" in src,
        "uses canonical CancellationInjectionFramework"
    )]


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


def check_control_workflows() -> list:
    src = _read(SRC)
    checks = []
    for wf in CONTROL_WORKFLOWS:
        checks.append(_check(f"workflow: {wf}", f'"{wf}"' in src))
    return checks


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


def check_schema_version() -> list:
    src = _read(SRC)
    return [_check("schema version cig-v1.0", "cig-v1.0" in src)]


def check_serde() -> list:
    src = _read(SRC)
    return [_check("Serialize/Deserialize derives",
                   "Serialize" in src and "Deserialize" in src)]


def check_test_count() -> list:
    src = _read(SRC)
    count = len(re.findall(r"#\[test\]", src))
    return [_check("inline tests >= 15", count >= 15, f"{count} tests")]


def check_spec_sections() -> list:
    content = _read(SPEC)
    if not content:
        return [_check("spec sections", False, "spec missing")]
    checks = []
    for section in ["Invariants", "Event Codes", "Error Codes", "Acceptance Criteria",
                    "Control Workflows"]:
        checks.append(_check(f"spec: {section}", section in content))
    return checks


def run_checks() -> dict:
    checks = []
    checks.extend(check_files())
    checks.extend(check_module_wired())
    checks.extend(check_canonical_import())
    checks.extend(check_types())
    checks.extend(check_ops())
    checks.extend(check_control_workflows())
    checks.extend(check_event_codes())
    checks.extend(check_error_codes())
    checks.extend(check_invariants())
    checks.extend(check_schema_version())
    checks.extend(check_serde())
    checks.extend(check_test_count())
    checks.extend(check_spec_sections())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])
    verdict = "PASS" if failing == 0 else "FAIL"

    return {
        "bead_id": "bd-3tpg",
        "title": "Cancel injection gate for control-plane workflows",
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
    logger = configure_test_logging("check_cancel_injection_gate")
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
    print(f"\nbd-3tpg verification: {result['verdict']} ({passing}/{total} checks pass)")
    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
