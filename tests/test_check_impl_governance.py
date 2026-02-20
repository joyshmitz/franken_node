"""Tests for scripts/check_impl_governance.py."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_impl_governance import (
    check_policy_exists,
    check_policy_rules,
    check_adr_reference,
    check_charter_xref,
    check_enforcement_section,
    REQUIRED_RULES,
)


def test_policy_exists():
    result = check_policy_exists()
    assert result["status"] == "PASS"
    assert result["id"] == "GOV-EXISTS"


def test_policy_all_rules_present():
    result = check_policy_rules()
    assert result["status"] == "PASS"
    for rule_name, found in result["details"]["rules"].items():
        assert found, f"Rule '{rule_name}' not found"


def test_required_rules_count():
    assert len(REQUIRED_RULES) == 4


def test_adr_reference():
    result = check_adr_reference()
    assert result["status"] == "PASS"
    assert result["details"]["adr_referenced"] is True


def test_charter_xref():
    result = check_charter_xref()
    assert result["status"] == "PASS"
    assert result["details"]["cross_referenced"] is True


def test_enforcement_section():
    result = check_enforcement_section()
    assert result["status"] == "PASS"
    assert result["details"]["enforcement_section"] is True
    assert result["details"]["ci_gate_documented"] is True
    assert result["details"]["review_checklist"] is True


def test_policy_file_has_scope():
    text = (ROOT / "docs" / "IMPLEMENTATION_GOVERNANCE.md").read_text()
    assert "## 1. Scope" in text


def test_policy_file_has_no_exceptions():
    text = (ROOT / "docs" / "IMPLEMENTATION_GOVERNANCE.md").read_text()
    assert "No exceptions" in text
