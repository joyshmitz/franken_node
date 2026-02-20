"""Tests for scripts/check_l2_oracle.py."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_l2_oracle import (
    check_design_exists,
    check_boundary_coverage,
    check_always_blocks,
    check_split_reference,
    check_l1_complement,
    REQUIRED_SECTIONS,
)


def test_design_exists():
    assert check_design_exists()["status"] == "PASS"


def test_boundary_coverage():
    result = check_boundary_coverage()
    assert result["status"] == "PASS"
    for s in REQUIRED_SECTIONS:
        assert result["details"]["sections"][s] is True


def test_always_blocks():
    result = check_always_blocks()
    assert result["status"] == "PASS"
    assert result["details"]["always_blocks"] is True


def test_split_reference():
    assert check_split_reference()["status"] == "PASS"


def test_l1_complement():
    result = check_l1_complement()
    assert result["status"] == "PASS"
    assert result["details"]["l1_referenced"] is True
    assert result["details"]["both_required"] is True


def test_design_has_integration():
    text = (ROOT / "docs" / "L2_ENGINE_BOUNDARY_ORACLE.md").read_text()
    assert "Integration" in text
