#!/usr/bin/env python3
"""Verification script for bd-3m6: disaster-recovery drills for control-plane failures.

Usage:
    python3 scripts/check_dr_drills.py              # human-readable
    python3 scripts/check_dr_drills.py --json        # machine-readable
    python3 scripts/check_dr_drills.py --self-test   # smoke-test
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

SPEC = ROOT / "docs" / "specs" / "section_10_8" / "bd-3m6_contract.md"
SCHEMA_FILE = ROOT / "fixtures" / "drills" / "drill_schema.json"
EVIDENCE = ROOT / "artifacts" / "section_10_8" / "bd-3m6" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_8" / "bd-3m6" / "verification_summary.md"

# The 5 drill scenarios
SCENARIOS = [
    {
        "scenario_id": "DR-001",
        "category": "evidence_ledger_loss",
        "json_file": "dr_001_evidence_ledger_loss.json",
        "severity": "high",
        "related_runbook": "RB-005",
    },
    {
        "scenario_id": "DR-002",
        "category": "trust_artifact_corruption",
        "json_file": "dr_002_trust_artifact_corruption.json",
        "severity": "critical",
        "related_runbook": "RB-001",
    },
    {
        "scenario_id": "DR-003",
        "category": "epoch_barrier_failure",
        "json_file": "dr_003_epoch_barrier_failure.json",
        "severity": "critical",
        "related_runbook": "RB-004",
    },
    {
        "scenario_id": "DR-004",
        "category": "federation_partition",
        "json_file": "dr_004_federation_partition.json",
        "severity": "high",
        "related_runbook": "RB-005",
    },
    {
        "scenario_id": "DR-005",
        "category": "proof_pipeline_outage",
        "json_file": "dr_005_proof_pipeline_outage.json",
        "severity": "high",
        "related_runbook": "RB-006",
    },
]

EVENT_CODES = ["DRD-001", "DRD-002", "DRD-003", "DRD-004", "DRD-005", "DRD-006"]

INVARIANTS = [
    "INV-DRD-DETERMINISTIC",
    "INV-DRD-ISOLATED",
    "INV-DRD-MEASURED",
    "INV-DRD-EVIDENCE",
    "INV-DRD-ABORT-SAFE",
]

REQUIRED_SCHEMA_FIELDS = [
    "scenario_id",
    "title",
    "category",
    "severity",
    "slo_seconds",
    "drill_interval",
    "fault_description",
    "fault_injection_steps",
    "recovery_steps",
    "verification_steps",
    "abort_conditions",
    "related_runbook",
    "cross_references",
]

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str) -> None:
    RESULTS.append({"name": name, "passed": passed, "detail": detail})


def _safe_rel(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


# -- Spec checks -------------------------------------------------------------


def check_spec_exists() -> None:
    ok = SPEC.is_file()
    _check("spec_exists", ok,
           f"Spec file {'found' if ok else 'MISSING'}: {_safe_rel(SPEC)}")


def check_spec_scenarios_documented() -> None:
    if not SPEC.is_file():
        _check("spec_scenarios", False, "spec file missing")
        return
    text = SPEC.read_text()
    missing = [s["category"] for s in SCENARIOS if s["category"] not in text]
    ok = len(missing) == 0
    _check("spec_scenarios", ok,
           "All 5 scenarios documented" if ok else f"Missing: {missing}")


def check_spec_scenario_ids() -> None:
    if not SPEC.is_file():
        _check("spec_scenario_ids", False, "spec file missing")
        return
    text = SPEC.read_text()
    ids = [s["scenario_id"] for s in SCENARIOS]
    missing = [sid for sid in ids if sid not in text]
    ok = len(missing) == 0
    _check("spec_scenario_ids", ok,
           "All 5 scenario IDs documented" if ok else f"Missing: {missing}")


def check_event_codes_in_spec() -> None:
    if not SPEC.is_file():
        for code in EVENT_CODES:
            _check(f"event_code_spec:{code}", False, "spec file missing")
        return
    text = SPEC.read_text()
    for code in EVENT_CODES:
        ok = code in text
        _check(f"event_code_spec:{code}", ok,
               "found" if ok else "NOT FOUND in spec")


def check_invariants_in_spec() -> None:
    if not SPEC.is_file():
        for inv in INVARIANTS:
            _check(f"invariant_spec:{inv}", False, "spec file missing")
        return
    text = SPEC.read_text()
    for inv in INVARIANTS:
        ok = inv in text
        _check(f"invariant_spec:{inv}", ok,
               "found" if ok else "NOT FOUND in spec")


# -- Schema checks -----------------------------------------------------------


def check_schema_exists() -> None:
    ok = SCHEMA_FILE.is_file()
    _check("schema_exists", ok,
           f"Schema file {'found' if ok else 'MISSING'}: {_safe_rel(SCHEMA_FILE)}")


def check_schema_valid_json() -> None:
    if not SCHEMA_FILE.is_file():
        _check("schema_valid_json", False, "Schema file MISSING")
        return
    try:
        data = json.loads(SCHEMA_FILE.read_text())
        ok = "$schema" in data and "properties" in data and "required" in data
        _check("schema_valid_json", ok,
               "Valid JSON Schema structure" if ok else "Missing $schema, properties, or required")
    except json.JSONDecodeError as exc:
        _check("schema_valid_json", False, f"JSON parse error: {exc}")


def check_schema_required_fields() -> None:
    if not SCHEMA_FILE.is_file():
        _check("schema_required_fields", False, "Schema file MISSING")
        return
    try:
        data = json.loads(SCHEMA_FILE.read_text())
        required = data.get("required", [])
        missing = [f for f in REQUIRED_SCHEMA_FIELDS if f not in required]
        ok = len(missing) == 0
        _check("schema_required_fields", ok,
               "All required fields in schema" if ok else f"Missing: {missing}")
    except json.JSONDecodeError as exc:
        _check("schema_required_fields", False, f"JSON parse error: {exc}")


def check_schema_category_enum() -> None:
    if not SCHEMA_FILE.is_file():
        _check("schema_category_enum", False, "Schema file MISSING")
        return
    try:
        data = json.loads(SCHEMA_FILE.read_text())
        enum_vals = data.get("properties", {}).get("category", {}).get("enum", [])
        expected = {s["category"] for s in SCENARIOS}
        ok = expected == set(enum_vals)
        _check("schema_category_enum", ok,
               "All 5 categories in schema enum" if ok
               else f"Mismatch: expected {expected}, got {set(enum_vals)}")
    except json.JSONDecodeError as exc:
        _check("schema_category_enum", False, f"JSON parse error: {exc}")


# -- Drill scenario JSON checks ----------------------------------------------


def check_json_drills_exist() -> None:
    for sc in SCENARIOS:
        json_path = ROOT / "fixtures" / "drills" / sc["json_file"]
        ok = json_path.is_file()
        _check(f"json_exists:{sc['category']}", ok,
               f"{'found' if ok else 'MISSING'}: {_safe_rel(json_path)}")


def check_json_drill_fields() -> None:
    for sc in SCENARIOS:
        json_path = ROOT / "fixtures" / "drills" / sc["json_file"]
        if not json_path.is_file():
            for field in REQUIRED_SCHEMA_FIELDS:
                _check(f"json_field:{sc['category']}:{field}", False, "JSON file MISSING")
            continue
        try:
            data = json.loads(json_path.read_text())
            for field in REQUIRED_SCHEMA_FIELDS:
                ok = field in data
                _check(f"json_field:{sc['category']}:{field}", ok,
                       "present" if ok else "MISSING")
        except json.JSONDecodeError as exc:
            for field in REQUIRED_SCHEMA_FIELDS:
                _check(f"json_field:{sc['category']}:{field}", False,
                       f"JSON parse error: {exc}")


def check_json_drill_ids() -> None:
    for sc in SCENARIOS:
        json_path = ROOT / "fixtures" / "drills" / sc["json_file"]
        if not json_path.is_file():
            _check(f"json_id:{sc['category']}", False, "JSON file MISSING")
            continue
        try:
            data = json.loads(json_path.read_text())
            actual = data.get("scenario_id", "")
            ok = actual == sc["scenario_id"]
            _check(f"json_id:{sc['category']}", ok,
                   f"scenario_id={actual}" if ok
                   else f"expected {sc['scenario_id']}, got {actual}")
        except json.JSONDecodeError as exc:
            _check(f"json_id:{sc['category']}", False, f"JSON parse error: {exc}")


def check_json_drill_categories() -> None:
    for sc in SCENARIOS:
        json_path = ROOT / "fixtures" / "drills" / sc["json_file"]
        if not json_path.is_file():
            _check(f"json_category:{sc['category']}", False, "JSON file MISSING")
            continue
        try:
            data = json.loads(json_path.read_text())
            actual = data.get("category", "")
            ok = actual == sc["category"]
            _check(f"json_category:{sc['category']}", ok,
                   f"category={actual}" if ok
                   else f"expected {sc['category']}, got {actual}")
        except json.JSONDecodeError as exc:
            _check(f"json_category:{sc['category']}", False, f"JSON parse error: {exc}")


def check_json_drill_severity() -> None:
    for sc in SCENARIOS:
        json_path = ROOT / "fixtures" / "drills" / sc["json_file"]
        if not json_path.is_file():
            _check(f"json_severity:{sc['category']}", False, "JSON file MISSING")
            continue
        try:
            data = json.loads(json_path.read_text())
            actual = data.get("severity", "")
            ok = actual == sc["severity"]
            _check(f"json_severity:{sc['category']}", ok,
                   f"severity={actual}" if ok
                   else f"expected {sc['severity']}, got {actual}")
        except json.JSONDecodeError as exc:
            _check(f"json_severity:{sc['category']}", False, f"JSON parse error: {exc}")


def check_json_drill_slo() -> None:
    for sc in SCENARIOS:
        json_path = ROOT / "fixtures" / "drills" / sc["json_file"]
        if not json_path.is_file():
            _check(f"json_slo:{sc['category']}", False, "JSON file MISSING")
            continue
        try:
            data = json.loads(json_path.read_text())
            slo = data.get("slo_seconds", 0)
            ok = isinstance(slo, int) and slo > 0
            _check(f"json_slo:{sc['category']}", ok,
                   f"slo_seconds={slo}" if ok else f"Invalid SLO: {slo}")
        except json.JSONDecodeError as exc:
            _check(f"json_slo:{sc['category']}", False, f"JSON parse error: {exc}")


def check_json_drill_interval() -> None:
    for sc in SCENARIOS:
        json_path = ROOT / "fixtures" / "drills" / sc["json_file"]
        if not json_path.is_file():
            _check(f"json_interval:{sc['category']}", False, "JSON file MISSING")
            continue
        try:
            data = json.loads(json_path.read_text())
            interval = data.get("drill_interval", "")
            ok = interval in ("weekly", "monthly")
            _check(f"json_interval:{sc['category']}", ok,
                   f"drill_interval={interval}" if ok
                   else f"Invalid interval: {interval}")
        except json.JSONDecodeError as exc:
            _check(f"json_interval:{sc['category']}", False, f"JSON parse error: {exc}")


def check_json_drill_fault_steps() -> None:
    for sc in SCENARIOS:
        json_path = ROOT / "fixtures" / "drills" / sc["json_file"]
        if not json_path.is_file():
            _check(f"json_fault_steps:{sc['category']}", False, "JSON file MISSING")
            continue
        try:
            data = json.loads(json_path.read_text())
            steps = data.get("fault_injection_steps", [])
            ok = isinstance(steps, list) and len(steps) > 0
            _check(f"json_fault_steps:{sc['category']}", ok,
                   f"{len(steps)} fault injection steps" if ok
                   else "MISSING or empty")
        except json.JSONDecodeError as exc:
            _check(f"json_fault_steps:{sc['category']}", False, f"JSON parse error: {exc}")


def check_json_drill_recovery_steps() -> None:
    for sc in SCENARIOS:
        json_path = ROOT / "fixtures" / "drills" / sc["json_file"]
        if not json_path.is_file():
            _check(f"json_recovery_steps:{sc['category']}", False, "JSON file MISSING")
            continue
        try:
            data = json.loads(json_path.read_text())
            steps = data.get("recovery_steps", [])
            ok = isinstance(steps, list) and len(steps) > 0
            _check(f"json_recovery_steps:{sc['category']}", ok,
                   f"{len(steps)} recovery steps" if ok else "MISSING or empty")
        except json.JSONDecodeError as exc:
            _check(f"json_recovery_steps:{sc['category']}", False, f"JSON parse error: {exc}")


def check_json_drill_verification_steps() -> None:
    for sc in SCENARIOS:
        json_path = ROOT / "fixtures" / "drills" / sc["json_file"]
        if not json_path.is_file():
            _check(f"json_verification_steps:{sc['category']}", False, "JSON file MISSING")
            continue
        try:
            data = json.loads(json_path.read_text())
            steps = data.get("verification_steps", [])
            ok = isinstance(steps, list) and len(steps) > 0
            _check(f"json_verification_steps:{sc['category']}", ok,
                   f"{len(steps)} verification steps" if ok else "MISSING or empty")
        except json.JSONDecodeError as exc:
            _check(f"json_verification_steps:{sc['category']}", False,
                   f"JSON parse error: {exc}")


def check_json_drill_abort_conditions() -> None:
    for sc in SCENARIOS:
        json_path = ROOT / "fixtures" / "drills" / sc["json_file"]
        if not json_path.is_file():
            _check(f"json_abort:{sc['category']}", False, "JSON file MISSING")
            continue
        try:
            data = json.loads(json_path.read_text())
            conditions = data.get("abort_conditions", [])
            ok = isinstance(conditions, list) and len(conditions) > 0
            _check(f"json_abort:{sc['category']}", ok,
                   f"{len(conditions)} abort conditions" if ok
                   else "MISSING or empty")
        except json.JSONDecodeError as exc:
            _check(f"json_abort:{sc['category']}", False, f"JSON parse error: {exc}")


def check_json_drill_related_runbook() -> None:
    for sc in SCENARIOS:
        json_path = ROOT / "fixtures" / "drills" / sc["json_file"]
        if not json_path.is_file():
            _check(f"json_runbook:{sc['category']}", False, "JSON file MISSING")
            continue
        try:
            data = json.loads(json_path.read_text())
            runbook = data.get("related_runbook", "")
            ok = isinstance(runbook, str) and bool(re.match(r"^RB-\d{3}$", runbook))
            _check(f"json_runbook:{sc['category']}", ok,
                   f"related_runbook={runbook}" if ok
                   else f"Invalid runbook ref: {runbook}")
        except json.JSONDecodeError as exc:
            _check(f"json_runbook:{sc['category']}", False, f"JSON parse error: {exc}")


def check_json_drill_cross_refs() -> None:
    for sc in SCENARIOS:
        json_path = ROOT / "fixtures" / "drills" / sc["json_file"]
        if not json_path.is_file():
            _check(f"json_cross_refs:{sc['category']}", False, "JSON file MISSING")
            continue
        try:
            data = json.loads(json_path.read_text())
            refs = data.get("cross_references", [])
            ok = isinstance(refs, list) and len(refs) > 0
            _check(f"json_cross_refs:{sc['category']}", ok,
                   f"{len(refs)} cross-references" if ok
                   else "EMPTY cross_references")
        except json.JSONDecodeError as exc:
            _check(f"json_cross_refs:{sc['category']}", False, f"JSON parse error: {exc}")


def check_json_drill_fault_description() -> None:
    for sc in SCENARIOS:
        json_path = ROOT / "fixtures" / "drills" / sc["json_file"]
        if not json_path.is_file():
            _check(f"json_fault_desc:{sc['category']}", False, "JSON file MISSING")
            continue
        try:
            data = json.loads(json_path.read_text())
            desc = data.get("fault_description", "")
            ok = isinstance(desc, str) and len(desc) > 10
            _check(f"json_fault_desc:{sc['category']}", ok,
                   "non-empty fault description" if ok
                   else "EMPTY or too short fault_description")
        except json.JSONDecodeError as exc:
            _check(f"json_fault_desc:{sc['category']}", False, f"JSON parse error: {exc}")


# -- Aggregate checks --------------------------------------------------------


def check_scenario_count() -> None:
    count = sum(
        1 for s in SCENARIOS
        if (ROOT / "fixtures" / "drills" / s["json_file"]).is_file()
    )
    ok = count == 5
    _check("scenario_count", ok,
           f"{count}/5 drill scenario files present"
           if ok else f"Incomplete: {count}/5")


def check_critical_scenarios_weekly() -> None:
    """Verify critical severity scenarios have weekly drill interval."""
    for sc in SCENARIOS:
        if sc["severity"] != "critical":
            continue
        json_path = ROOT / "fixtures" / "drills" / sc["json_file"]
        if not json_path.is_file():
            _check(f"critical_weekly:{sc['category']}", False, "JSON file MISSING")
            continue
        try:
            data = json.loads(json_path.read_text())
            interval = data.get("drill_interval", "")
            ok = interval == "weekly"
            _check(f"critical_weekly:{sc['category']}", ok,
                   f"critical scenario drilled {interval}" if ok
                   else f"Expected weekly, got {interval}")
        except json.JSONDecodeError as exc:
            _check(f"critical_weekly:{sc['category']}", False, f"JSON parse error: {exc}")


# -- Evidence checks ---------------------------------------------------------


def check_verification_evidence() -> None:
    if not EVIDENCE.is_file():
        _check("verification_evidence", False,
               f"Evidence file MISSING: {_safe_rel(EVIDENCE)}")
        return
    try:
        data = json.loads(EVIDENCE.read_text())
        ok = data.get("bead_id") == "bd-3m6" and data.get("status") == "pass"
        _check("verification_evidence", ok,
               "Evidence file valid" if ok
               else "Evidence has incorrect bead_id or status")
    except (json.JSONDecodeError, KeyError) as exc:
        _check("verification_evidence", False, f"Evidence parse error: {exc}")


def check_verification_summary() -> None:
    ok = SUMMARY.is_file()
    _check("verification_summary", ok,
           f"Summary file {'found' if ok else 'MISSING'}: {_safe_rel(SUMMARY)}")


# -- Runner ------------------------------------------------------------------


ALL_CHECKS = [
    check_spec_exists,
    check_spec_scenarios_documented,
    check_spec_scenario_ids,
    check_event_codes_in_spec,
    check_invariants_in_spec,
    check_schema_exists,
    check_schema_valid_json,
    check_schema_required_fields,
    check_schema_category_enum,
    check_json_drills_exist,
    check_json_drill_fields,
    check_json_drill_ids,
    check_json_drill_categories,
    check_json_drill_severity,
    check_json_drill_slo,
    check_json_drill_interval,
    check_json_drill_fault_steps,
    check_json_drill_recovery_steps,
    check_json_drill_verification_steps,
    check_json_drill_abort_conditions,
    check_json_drill_related_runbook,
    check_json_drill_cross_refs,
    check_json_drill_fault_description,
    check_scenario_count,
    check_critical_scenarios_weekly,
    check_verification_evidence,
    check_verification_summary,
]


def run_all() -> dict[str, Any]:
    RESULTS.clear()
    for fn in ALL_CHECKS:
        fn()
    passed = sum(1 for r in RESULTS if r["passed"])
    total = len(RESULTS)
    failed = total - passed
    return {
        "bead_id": "bd-3m6",
        "section": "10.8",
        "title": "Disaster-recovery drills for control-plane failures",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "status": "pass" if failed == 0 else "fail",
        "passed": passed,
        "failed": failed,
        "total": total,
        "all_passed": failed == 0,
        "checks": list(RESULTS),
    }


def self_test() -> bool:
    result = run_all()
    assert isinstance(result, dict)
    assert result["bead_id"] == "bd-3m6"
    assert result["section"] == "10.8"
    assert isinstance(result["checks"], list)
    assert result["total"] == len(result["checks"])
    assert result["passed"] <= result["total"]
    assert result["failed"] == result["total"] - result["passed"]
    assert result["verdict"] in ("PASS", "FAIL")
    for check in result["checks"]:
        assert "name" in check
        assert "passed" in check
        assert "detail" in check
    print("self_test passed")
    return True


def main() -> None:
    logger = configure_test_logging("check_dr_drills")
    if "--self-test" in sys.argv:
        self_test()
        return

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print("bd-3m6: Disaster-recovery drills for control-plane failures")
        print("=" * 60)
        for c in result["checks"]:
            mark = "PASS" if c["passed"] else "FAIL"
            print(f"  [{mark}] {c['name']}: {c['detail']}")
        print(f"\n  {result['passed']}/{result['total']} checks passed"
              f" (verdict={result['verdict']})")
        if result["verdict"] != "PASS":
            sys.exit(1)


if __name__ == "__main__":
    main()
