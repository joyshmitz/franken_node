#!/usr/bin/env python3
"""Tests for bd-n9r e2e config precedence gate."""

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tests" / "e2e" / "config_profile_resolution.sh"
OUT_DIR = ROOT / "artifacts" / "section_bootstrap" / "bd-n9r"
CHECKS_JSON = OUT_DIR / "contract_checks.json"
SNAPSHOT_JSON = OUT_DIR / "resolved_config_snapshot.json"


def run_gate() -> None:
    subprocess.run([str(SCRIPT)], check=True, cwd=ROOT)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_gate_script_exists_and_executable():
    assert SCRIPT.exists()
    assert os.access(SCRIPT, os.X_OK)


def test_gate_runs_and_emits_pass_verdict():
    run_gate()
    payload = load_json(CHECKS_JSON)
    assert payload["bead_id"] == "bd-n9r"
    assert payload["verdict"] == "PASS"
    assert payload["checks_passed"] == payload["checks_total"]


def test_expected_contract_checks_are_present():
    run_gate()
    payload = load_json(CHECKS_JSON)
    checks = {entry["check"]: entry for entry in payload["checks"]}

    for check_name in (
        "resolver_entrypoint",
        "env_override_layer",
        "merge_decision_struct",
        "main_init_uses_resolver",
        "main_doctor_outputs_decisions",
        "cli_init_config_option",
        "cli_doctor_config_option",
        "cli_profile_options",
        "contract_precedence_doc",
        "snapshot_written",
    ):
        assert check_name in checks
        assert checks[check_name]["passed"], f"failed check: {check_name}"


def test_snapshot_has_deterministic_precedence_shape():
    run_gate()
    snapshot = load_json(SNAPSHOT_JSON)

    assert snapshot["schema_version"] == "config-resolution-snapshot-v1"
    assert snapshot["source_precedence"] == "CLI > env > profile-block > file-base > defaults"
    assert snapshot["selected_profile"] == "legacy-risky"

    resolved = snapshot["resolved_config"]
    assert resolved["profile"] == "legacy-risky"
    assert resolved["migration"]["autofix"] is False
    assert resolved["registry"]["minimum_assurance_level"] == 4
