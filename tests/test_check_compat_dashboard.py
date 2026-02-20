"""Tests for scripts/check_compat_dashboard.py."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_compat_dashboard import (
    check_spec_exists, check_schema_exists, check_views,
    check_data_sources, check_ci_integration, REQUIRED_VIEWS,
)


def test_spec_exists():
    assert check_spec_exists()["status"] == "PASS"

def test_schema_exists():
    assert check_schema_exists()["status"] == "PASS"

def test_views():
    result = check_views()
    assert result["status"] == "PASS"
    for v in REQUIRED_VIEWS:
        assert result["details"]["views"][v] is True

def test_data_sources():
    result = check_data_sources()
    assert result["status"] == "PASS"

def test_ci_integration():
    assert check_ci_integration()["status"] == "PASS"

def test_schema_valid_json():
    data = json.loads((ROOT / "schemas" / "compat_dashboard.schema.json").read_text())
    assert "overall" in data.get("required", [])

def test_required_views_count():
    assert len(REQUIRED_VIEWS) == 4
