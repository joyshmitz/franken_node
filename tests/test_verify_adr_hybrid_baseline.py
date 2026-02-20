"""Tests for scripts/verify_adr_hybrid_baseline.py."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from verify_adr_hybrid_baseline import (
    check_adr_exists,
    check_adr_status,
    check_adr_rules,
    check_adr_references,
    check_charter_xref,
    REQUIRED_RULES,
)


def test_adr_exists():
    result = check_adr_exists()
    assert result["status"] == "PASS"
    assert result["id"] == "ADR-EXISTS"
    assert "size_bytes" in result["details"]


def test_adr_status_accepted():
    result = check_adr_status()
    assert result["status"] == "PASS"
    assert result["details"]["status"] == "Accepted"


def test_adr_all_rules_present():
    result = check_adr_rules()
    assert result["status"] == "PASS"
    for rule_name, found in result["details"]["rules"].items():
        assert found, f"Rule '{rule_name}' not found in ADR"


def test_required_rules_count():
    assert len(REQUIRED_RULES) == 6


def test_adr_references_plan():
    result = check_adr_references()
    assert result["status"] == "PASS"
    refs = {r["name"]: r["found"] for r in result["details"]["references"]}
    assert refs["PLAN_TO_CREATE_FRANKEN_NODE"] is True
    assert refs["PRODUCT_CHARTER"] is True
    assert refs["ENGINE_SPLIT_CONTRACT"] is True


def test_charter_cross_references_adr():
    result = check_charter_xref()
    assert result["status"] == "PASS"
    assert result["details"]["cross_referenced"] is True


def test_adr_file_content_has_title():
    adr_path = ROOT / "docs" / "adr" / "ADR-001-hybrid-baseline-strategy.md"
    text = adr_path.read_text()
    assert "# ADR-001: Hybrid Baseline Strategy" in text


def test_adr_file_has_consequences_section():
    adr_path = ROOT / "docs" / "adr" / "ADR-001-hybrid-baseline-strategy.md"
    text = adr_path.read_text()
    assert "## Consequences" in text
