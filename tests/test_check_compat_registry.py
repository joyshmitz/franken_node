"""Tests for scripts/check_compat_registry.py."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_compat_registry import (
    check_registry_exists,
    check_schema_exists,
    check_registry_structure,
    check_entry_fields,
    check_unique_ids,
    check_band_coverage,
    VALID_BANDS,
    VALID_SHIM_TYPES,
    VALID_ORACLE_STATUSES,
    ID_PATTERN,
)


def test_registry_exists():
    result = check_registry_exists()
    assert result["status"] == "PASS"


def test_schema_exists():
    result = check_schema_exists()
    assert result["status"] == "PASS"


def test_registry_structure():
    result = check_registry_structure()
    assert result["status"] == "PASS"
    assert result["details"]["behavior_count"] >= 1


def test_entry_fields_valid():
    result = check_entry_fields()
    assert result["status"] == "PASS"
    assert len(result["details"]["errors"]) == 0
    for entry in result["details"]["entries"]:
        assert entry["valid"] is True


def test_unique_ids():
    result = check_unique_ids()
    assert result["status"] == "PASS"
    assert result["details"]["total_ids"] == result["details"]["unique_ids"]


def test_band_coverage():
    result = check_band_coverage()
    assert result["status"] == "PASS"
    assert result["details"]["bands_represented"]["core"] is True


def test_valid_bands_set():
    assert VALID_BANDS == {"core", "high-value", "edge", "unsafe"}


def test_valid_shim_types_set():
    assert VALID_SHIM_TYPES == {"native", "polyfill", "bridge", "stub"}


def test_valid_oracle_statuses_set():
    assert VALID_ORACLE_STATUSES == {"validated", "pending", "not-applicable"}


def test_id_pattern_valid():
    assert ID_PATTERN.match("compat:fs:readFile")
    assert ID_PATTERN.match("compat:http:createServer")
    assert not ID_PATTERN.match("invalid-id")
    assert not ID_PATTERN.match("compat:fs")


def test_registry_json_parses():
    data = json.loads((ROOT / "docs" / "COMPATIBILITY_REGISTRY.json").read_text())
    assert data["schema_version"] == "1.0"
    assert isinstance(data["behaviors"], list)
    assert len(data["behaviors"]) >= 5
