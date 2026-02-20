"""Tests for scripts/check_divergence_ledger.py."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_divergence_ledger import (
    check_ledger_exists,
    check_schema_exists,
    check_ledger_structure,
    check_entry_fields,
    check_rationale_present,
    check_unique_ids,
    VALID_BANDS,
    VALID_RISK_TIERS,
    VALID_STATUSES,
    ID_PATTERN,
)


def test_ledger_exists():
    result = check_ledger_exists()
    assert result["status"] == "PASS"


def test_schema_exists():
    result = check_schema_exists()
    assert result["status"] == "PASS"


def test_ledger_structure():
    result = check_ledger_structure()
    assert result["status"] == "PASS"
    assert result["details"]["entry_count"] >= 1


def test_entry_fields_valid():
    result = check_entry_fields()
    assert result["status"] == "PASS"
    assert len(result["details"]["errors"]) == 0


def test_rationale_present():
    result = check_rationale_present()
    assert result["status"] == "PASS"
    assert result["details"]["entries_with_rationale"] == result["details"]["total_entries"]


def test_unique_ids():
    result = check_unique_ids()
    assert result["status"] == "PASS"
    assert result["details"]["total"] == result["details"]["unique"]


def test_id_pattern():
    assert ID_PATTERN.match("DIV-001")
    assert ID_PATTERN.match("DIV-999")
    assert not ID_PATTERN.match("DIV-01")
    assert not ID_PATTERN.match("div-001")


def test_valid_enums():
    assert VALID_BANDS == {"core", "high-value", "edge", "unsafe"}
    assert VALID_RISK_TIERS == {"critical", "high", "medium", "low"}
    assert VALID_STATUSES == {"accepted", "under-review", "deprecated"}


def test_ledger_json_content():
    data = json.loads((ROOT / "docs" / "DIVERGENCE_LEDGER.json").read_text())
    assert data["schema_version"] == "1.0"
    assert len(data["entries"]) >= 2
    # Verify first entry has rationale
    assert len(data["entries"][0]["rationale"]) > 10
