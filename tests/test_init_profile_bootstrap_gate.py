#!/usr/bin/env python3
"""Tests for bd-32e init bootstrap gate."""

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tests" / "e2e" / "init_profile_bootstrap.sh"
OUT_DIR = ROOT / "artifacts" / "section_bootstrap" / "bd-32e"
CHECKS_JSON = OUT_DIR / "init_contract_checks.json"
SNAPSHOTS_JSON = OUT_DIR / "init_snapshots.json"


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
    assert payload["bead_id"] == "bd-32e"
    assert payload["verdict"] == "PASS"
    assert payload["checks_passed"] == payload["checks_total"]


def test_expected_contract_checks_are_present() -> None:
    run_gate()
    payload = load_json(CHECKS_JSON)
    checks = {entry["check"]: entry for entry in payload["checks"]}

    for check_name in (
        "cli_init_overwrite_flag",
        "cli_init_backup_flag",
        "cli_init_json_flag",
        "cli_init_trace_id_flag",
        "init_trace_id_default",
        "init_profile_template_embedded",
        "init_flag_validation",
        "init_write_policy_function",
        "init_mutual_exclusion_error",
        "init_writes_profile_example_file",
        "init_non_destructive_default",
        "init_contract_sections_present",
        "snapshots_written",
        "snapshots_hash_stable",
    ):
        assert check_name in checks
        assert checks[check_name]["passed"], f"failed check: {check_name}"


def test_snapshots_cover_clean_abort_backup_stdout_scenarios() -> None:
    run_gate()
    snapshots = load_json(SNAPSHOTS_JSON)

    assert snapshots["schema_version"] == "init-bootstrap-snapshots-v1"
    scenarios = {entry["scenario"]: entry for entry in snapshots["scenarios"]}

    for name in (
        "clean_out_dir",
        "existing_files_abort_default",
        "backup_existing_rewrite",
        "stdout_only",
    ):
        assert name in scenarios

    clean = scenarios["clean_out_dir"]
    assert clean["expected"]["wrote_to_stdout"] is False
    assert len(clean["expected"]["file_actions"]) == 2

    abort = scenarios["existing_files_abort_default"]
    assert abort["expected_error"]["code"] == "INIT-EXISTS-001"
    assert "overwrite" in abort["expected_error"]["message_contains"]

    backup = scenarios["backup_existing_rewrite"]
    assert backup["expected"]["file_actions"][0]["action"] == "backed_up_and_overwritten"

    stdout_only = scenarios["stdout_only"]
    assert stdout_only["expected"]["wrote_to_stdout"] is True
    assert stdout_only["expected"]["stdout_config_toml_non_empty"] is True
