"""Tests for scripts/check_minimized_fixtures.py."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_minimized_fixtures import (
    check_spec_exists,
    check_dir_exists,
    check_strategies,
    check_fixture_format,
    check_integration,
    REQUIRED_STRATEGIES,
)


def test_spec_exists():
    assert check_spec_exists()["status"] == "PASS"


def test_dir_exists():
    assert check_dir_exists()["status"] == "PASS"


def test_strategies_documented():
    result = check_strategies()
    assert result["status"] == "PASS"
    for s in REQUIRED_STRATEGIES:
        assert result["details"]["strategies"][s] is True


def test_required_strategies_count():
    assert len(REQUIRED_STRATEGIES) == 3


def test_fixture_format():
    result = check_fixture_format()
    assert result["status"] == "PASS"
    assert result["details"]["extra_fields_documented"] is True


def test_integration():
    result = check_integration()
    assert result["status"] == "PASS"
    assert result["details"]["l1_integration"] is True
    assert result["details"]["ledger_integration"] is True


def test_spec_has_storage_section():
    text = (ROOT / "docs" / "MINIMIZED_FIXTURE_SPEC.md").read_text()
    assert "## 4. Storage" in text
