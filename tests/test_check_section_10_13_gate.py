"""Tests for scripts/check_section_10_13_gate.py (section 10.13 verification gate)."""

import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_section_10_13_gate.py"

# The gate script uses a global CHECKS list and direct print statements,
# so we import and test the check() helper and structural aspects.
spec = importlib.util.spec_from_file_location("check_section_10_13_gate", str(SCRIPT))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# check() helper
# ---------------------------------------------------------------------------

class TestCheckHelper:
    def setup_method(self):
        """Clear global CHECKS list before each test."""
        mod.CHECKS.clear()

    def test_passing_check(self):
        result = mod.check("TEST-001", "test check", True, "all good")
        assert result is True
        assert len(mod.CHECKS) == 1
        assert mod.CHECKS[0]["id"] == "TEST-001"
        assert mod.CHECKS[0]["status"] == "PASS"
        assert mod.CHECKS[0]["details"] == "all good"

    def test_failing_check(self):
        result = mod.check("TEST-002", "test fail", False, "broken")
        assert result is False
        assert len(mod.CHECKS) == 1
        assert mod.CHECKS[0]["status"] == "FAIL"

    def test_check_without_details(self):
        mod.check("TEST-003", "no details", True)
        assert "details" not in mod.CHECKS[0]

    def test_multiple_checks_accumulate(self):
        mod.check("A", "first", True)
        mod.check("B", "second", False)
        mod.check("C", "third", True)
        assert len(mod.CHECKS) == 3
        ids = [c["id"] for c in mod.CHECKS]
        assert ids == ["A", "B", "C"]

    def test_check_entry_structure(self):
        mod.check("STRUCT", "structure test", True, "details here")
        entry = mod.CHECKS[0]
        assert set(entry.keys()) == {"id", "description", "status", "details"}


# ---------------------------------------------------------------------------
# Beads list
# ---------------------------------------------------------------------------

def test_beads_list_not_empty():
    """The gate script defines a list of section 10.13 beads."""
    # The beads list is defined inside main(), so we check by reading the source
    source = SCRIPT.read_text()
    assert "beads_10_13" in source
    # Should have at least 40 beads
    assert source.count('"bd-') >= 40


# ---------------------------------------------------------------------------
# Evidence directory structure
# ---------------------------------------------------------------------------

def test_evidence_artifact_paths():
    """Verify the gate writes evidence to the expected path."""
    source = SCRIPT.read_text()
    assert "artifacts/section_10_13/bd-3uoo" in source
    assert "verification_evidence.json" in source


# ---------------------------------------------------------------------------
# Gate thresholds
# ---------------------------------------------------------------------------

def test_rust_test_threshold():
    """Gate requires >= 500 Rust tests."""
    source = SCRIPT.read_text()
    assert "rust_tests >= 500" in source


def test_python_test_threshold():
    """Gate requires >= 100 Python tests."""
    source = SCRIPT.read_text()
    assert "py_tests >= 100" in source


def test_evidence_bead_threshold():
    """Gate requires >= 40 beads with PASS evidence."""
    source = SCRIPT.read_text()
    assert "evidence_pass >= 40" in source


def test_module_count_threshold():
    """Gate requires >= 30 connector modules."""
    source = SCRIPT.read_text()
    assert "modules >= 30" in source


def test_spec_contract_threshold():
    """Gate requires >= 40 spec contracts."""
    source = SCRIPT.read_text()
    assert "len(specs) >= 40" in source


def test_integration_test_threshold():
    """Gate requires >= 25 integration test files."""
    source = SCRIPT.read_text()
    assert "len(integ_files) >= 25" in source


# ---------------------------------------------------------------------------
# Evidence bead list completeness
# ---------------------------------------------------------------------------

def test_beads_list_includes_known_beads():
    """Spot-check that well-known 10.13 beads are in the list."""
    source = SCRIPT.read_text()
    # Known 10.13 beads that should be present
    known_beads = ["bd-2gh", "bd-1rk", "bd-3ua7", "bd-3n2u"]
    for bead in known_beads:
        assert f'"{bead}"' in source, f"Missing bead: {bead}"


# ---------------------------------------------------------------------------
# Gate evidence structure
# ---------------------------------------------------------------------------

def test_evidence_output_has_required_fields():
    """Verify the evidence dict template has required fields."""
    source = SCRIPT.read_text()
    assert '"gate":' in source
    assert '"bead":' in source
    assert '"section":' in source
    assert '"verdict":' in source
    assert '"checks":' in source
    assert '"summary":' in source
