"""Tests for scripts/check_lockstep_runner.py."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_lockstep_runner import (
    check_design_exists,
    check_config_schema,
    check_phases_documented,
    check_delta_format,
    check_release_gating,
    REQUIRED_PHASES,
)


def test_design_exists():
    assert check_design_exists()["status"] == "PASS"


def test_config_schema():
    result = check_config_schema()
    assert result["status"] == "PASS"
    assert "runtimes" in result["details"]["required_fields"]


def test_phases_documented():
    result = check_phases_documented()
    assert result["status"] == "PASS"
    for phase in REQUIRED_PHASES:
        assert result["details"]["phases"][phase] is True, f"Phase '{phase}' not found"


def test_required_phases_count():
    assert len(REQUIRED_PHASES) == 5


def test_delta_format():
    result = check_delta_format()
    assert result["status"] == "PASS"
    assert result["details"]["report_documented"] is True
    assert result["details"]["json_format"] is True


def test_release_gating():
    result = check_release_gating()
    assert result["status"] == "PASS"
    assert result["details"]["core_blocks_release"] is True


def test_config_schema_json_valid():
    data = json.loads((ROOT / "schemas" / "lockstep_runner_config.schema.json").read_text())
    assert data["properties"]["runtimes"]["type"] == "array"


def test_design_has_architecture_section():
    text = (ROOT / "docs" / "L1_LOCKSTEP_RUNNER.md").read_text()
    assert "## 2. Architecture" in text
