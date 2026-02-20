"""Tests for scripts/check_compat_modes.py."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_compat_modes import (
    check_policy_exists,
    check_modes_defined,
    check_default_mode,
    check_band_coverage,
    check_unsafe_opt_in,
    check_bands_reference,
    REQUIRED_MODES,
    REQUIRED_BANDS,
)


def test_policy_exists():
    assert check_policy_exists()["status"] == "PASS"


def test_all_modes_defined():
    result = check_modes_defined()
    assert result["status"] == "PASS"
    for mode in REQUIRED_MODES:
        assert result["details"]["modes"][mode] is True


def test_default_is_balanced():
    result = check_default_mode()
    assert result["status"] == "PASS"
    assert result["details"]["default_mode"] == "balanced"


def test_band_coverage_complete():
    result = check_band_coverage()
    assert result["status"] == "PASS"
    for mode in REQUIRED_MODES:
        for band in REQUIRED_BANDS:
            assert result["details"]["coverage"][mode][band] is True, \
                f"Mode '{mode}' missing band '{band}'"


def test_unsafe_opt_in_documented():
    result = check_unsafe_opt_in()
    assert result["status"] == "PASS"
    assert result["details"]["opt_in_documented"] is True


def test_bands_reference():
    result = check_bands_reference()
    assert result["status"] == "PASS"


def test_required_modes_count():
    assert len(REQUIRED_MODES) == 3


def test_policy_has_enforcement():
    text = (ROOT / "docs" / "COMPATIBILITY_MODE_POLICY.md").read_text()
    assert "Enforcement" in text


def test_policy_has_config_section():
    text = (ROOT / "docs" / "COMPATIBILITY_MODE_POLICY.md").read_text()
    assert "[compatibility]" in text
