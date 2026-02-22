"""Tests for scripts/check_obligation_channel_protocol.py (bd-2ah)."""

import importlib.util
import json
import os
import subprocess
import sys
from unittest import mock

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_obligation_channel_protocol.py")

spec = importlib.util.spec_from_file_location(
    "check_mod", os.path.join(ROOT, "scripts", "check_obligation_channel_protocol.py")
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_verdict_pass(self):
        result = mod.self_test()
        assert result["verdict"] == "PASS"

    def test_self_test_has_required_keys(self):
        result = mod.self_test()
        assert "name" in result
        assert "bead" in result
        assert "section" in result
        assert "passed" in result
        assert "failed" in result
        assert "checks" in result
        assert "verdict" in result


class TestAllChecksPass:
    def test_all_checks_pass(self):
        result = mod.run_all()
        failed = [c for c in result["checks"] if not c["passed"]]
        assert len(failed) == 0, f"Failed checks: {[c['check'] for c in failed]}"

    def test_verdict_is_pass(self):
        result = mod.run_all()
        assert result["verdict"] == "PASS"


class TestJsonOutput:
    def test_json_output_format(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--json"], capture_output=True, text=True
        )
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-2ah"
        assert data["section"] == "10.11"
        assert isinstance(data["checks"], list)

    def test_json_verdict_field(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--json"], capture_output=True, text=True
        )
        data = json.loads(result.stdout)
        assert data["verdict"] in ("PASS", "FAIL")

    def test_json_checks_have_required_fields(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--json"], capture_output=True, text=True
        )
        data = json.loads(result.stdout)
        for check in data["checks"]:
            assert "check" in check
            assert "passed" in check
            assert "detail" in check


class TestMissingSources:
    def test_missing_source_detected(self):
        with mock.patch.object(mod, "SOURCE_RS", mod.ROOT / "nonexistent.rs"):
            checks = mod._checks()
            source_check = next(c for c in checks if c["check"] == "source_file_exists")
            assert source_check["passed"] is False

    def test_missing_spec_detected(self):
        with mock.patch.object(mod, "SPEC_PATH", mod.ROOT / "nonexistent.md"):
            checks = mod._checks()
            spec_check = next(c for c in checks if c["check"] == "spec_contract_exists")
            assert spec_check["passed"] is False


class TestCheckStructure:
    def test_check_structure(self):
        checks = mod._checks()
        for check in checks:
            assert isinstance(check, dict)
            assert "check" in check
            assert "passed" in check
            assert "detail" in check
            assert isinstance(check["passed"], bool)

    def test_minimum_check_count(self):
        checks = mod._checks()
        assert len(checks) >= 40


class TestEventCodesPresent:
    def test_event_codes_list_complete(self):
        assert len(mod.EVENT_CODES) == 12

    def test_error_codes_list_complete(self):
        assert len(mod.ERROR_CODES) == 10

    def test_invariants_list_complete(self):
        assert len(mod.INVARIANTS) == 6


class TestCliSelfTest:
    def test_cli_self_test_exits_zero(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--self-test"], capture_output=True, text=True
        )
        assert result.returncode == 0
        assert "self_test passed" in result.stdout


class TestSpecificChecks:
    @pytest.fixture(scope="class")
    def results(self):
        return {c["check"]: c for c in mod.run_all()["checks"]}

    def test_source_file_exists(self, results):
        assert results["source_file_exists"]["passed"]

    def test_module_wired(self, results):
        assert results["module_wired_in_mod_rs"]["passed"]

    def test_spec_exists(self, results):
        assert results["spec_contract_exists"]["passed"]

    def test_schema_version(self, results):
        assert results["schema_version"]["passed"]

    def test_serde_derives(self, results):
        assert results["serde_derives"]["passed"]

    def test_btreemap_usage(self, results):
        assert results["btreemap_usage"]["passed"]

    def test_unit_test_count(self, results):
        assert results["unit_test_count"]["passed"]

    def test_cfg_test_module(self, results):
        assert results["cfg_test_module"]["passed"]
