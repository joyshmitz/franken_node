"""Tests for scripts/check_compat_bands.py."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_compat_bands import (
    check_bands_doc_exists,
    check_all_bands_defined,
    check_band_content,
    check_modes_defined,
    check_mode_band_matrix,
    check_plan_reference,
    REQUIRED_BANDS,
    REQUIRED_MODES,
)


def test_bands_doc_exists():
    result = check_bands_doc_exists()
    assert result["status"] == "PASS"


def test_all_four_bands_defined():
    result = check_all_bands_defined()
    assert result["status"] == "PASS"
    for band in REQUIRED_BANDS:
        assert result["details"]["bands"][band] is True, f"Band '{band}' not found"


def test_required_bands_count():
    assert len(REQUIRED_BANDS) == 4
    assert "core" in REQUIRED_BANDS
    assert "unsafe" in REQUIRED_BANDS


def test_band_content_complete():
    result = check_band_content()
    assert result["status"] == "PASS"
    for band in REQUIRED_BANDS:
        entry = result["details"]["bands"][band]
        assert entry["has_priority"], f"Band '{band}' missing priority"
        assert entry["has_examples"], f"Band '{band}' missing examples"
        assert entry["has_divergence"], f"Band '{band}' missing divergence handling"


def test_all_three_modes_defined():
    result = check_modes_defined()
    assert result["status"] == "PASS"
    for mode in REQUIRED_MODES:
        assert result["details"]["modes"][mode] is True, f"Mode '{mode}' not found"


def test_required_modes_count():
    assert len(REQUIRED_MODES) == 3
    assert "strict" in REQUIRED_MODES
    assert "balanced" in REQUIRED_MODES
    assert "legacy-risky" in REQUIRED_MODES


def test_mode_band_matrix_complete():
    result = check_mode_band_matrix()
    assert result["status"] == "PASS"
    assert result["details"]["matrix_cells"] >= 12


def test_plan_reference():
    result = check_plan_reference()
    assert result["status"] == "PASS"
    assert result["details"]["plan_referenced"] is True


def test_bands_doc_has_oracle_section():
    text = (ROOT / "docs" / "COMPATIBILITY_BANDS.md").read_text()
    assert "Oracle Integration" in text or "oracle" in text.lower()


def test_bands_doc_has_configuration():
    text = (ROOT / "docs" / "COMPATIBILITY_BANDS.md").read_text()
    assert "[compatibility]" in text
    assert 'mode = "balanced"' in text
