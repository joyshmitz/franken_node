#!/usr/bin/env python3
"""Tests for bd-1pk doctor diagnostics gate."""

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tests" / "e2e" / "doctor_command_diagnostics.sh"
OUT_DIR = ROOT / "artifacts" / "section_bootstrap" / "bd-1pk"
CHECKS_JSON = OUT_DIR / "doctor_contract_checks.json"
MATRIX_JSON = OUT_DIR / "doctor_checks_matrix.json"
HEALTHY_JSON = OUT_DIR / "doctor_report_healthy.json"
DEGRADED_JSON = OUT_DIR / "doctor_report_degraded.json"
FAILURE_JSON = OUT_DIR / "doctor_report_failure.json"


def run_gate() -> None:
    subprocess.run([str(SCRIPT)], check=True, cwd=ROOT)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_gate_script_exists_and_executable() -> None:
    assert SCRIPT.exists()
    assert os.access(SCRIPT, os.X_OK)


def test_gate_runs_and_emits_pass_verdict() -> None:
    run_gate()
    payload = load_json(CHECKS_JSON)
    assert payload["bead_id"] == "bd-1pk"
    assert payload["verdict"] == "PASS"
    assert payload["checks_passed"] == payload["checks_total"]


def test_expected_contract_checks_are_present() -> None:
    run_gate()
    payload = load_json(CHECKS_JSON)
    checks = {entry["check"]: entry for entry in payload["checks"]}

    for check_name in (
        "doctor_args_json_flag",
        "doctor_args_trace_id_flag",
        "doctor_report_has_structured_logs",
        "doctor_report_has_merge_decisions",
        "doctor_builder_with_cwd",
        "doctor_json_output_path",
        "doctor_human_output_path",
        "doctor_code_order_deterministic",
        "contract_has_matrix_and_schema",
        "matrix_written",
        "healthy_report_written",
        "degraded_report_written",
        "failure_report_written",
        "healthy_report_deterministic_hash",
    ):
        assert check_name in checks
        assert checks[check_name]["passed"], f"failed check: {check_name}"


def test_sample_reports_match_expected_overall_states() -> None:
    run_gate()
    matrix = load_json(MATRIX_JSON)
    healthy = load_json(HEALTHY_JSON)
    degraded = load_json(DEGRADED_JSON)
    failure = load_json(FAILURE_JSON)

    assert matrix["schema_version"] == "doctor-check-matrix-v1"
    assert len(matrix["checks"]) == 8

    assert healthy["overall_status"] == "pass"
    assert healthy["status_counts"]["fail"] == 0
    assert healthy["status_counts"]["warn"] == 0

    assert degraded["overall_status"] == "warn"
    assert degraded["status_counts"]["warn"] > 0
    assert degraded["status_counts"]["fail"] == 0

    assert failure["overall_status"] == "fail"
    assert failure["status_counts"]["fail"] >= 1
    assert any(check["code"] == "DR-ENV-007" and check["status"] == "fail" for check in failure["checks"])
