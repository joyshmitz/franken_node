"""Tests for scripts/check_epoch_integration.py (bd-2gr)."""

import importlib.util
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_epoch_integration.py")

spec = importlib.util.spec_from_file_location("check_epoch_integration", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestJsonOutput:
    def test_json_output_shape(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert data["bead_id"] == "bd-2gr"
        assert data["section"] == "10.11"
        assert isinstance(data["checks"], list)

    def test_verdict_field(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert data["verdict"] in ("PASS", "FAIL")

    def test_checks_have_required_fields(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        for check in data["checks"]:
            assert "name" in check
            assert "passed" in check
            assert "detail" in check

    def test_minimum_check_count(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert len(data["checks"]) >= 40

    def test_cli_self_test(self):
        result = subprocess.run([sys.executable, SCRIPT, "--self-test"], capture_output=True, text=True)
        assert result.returncode == 0
        assert "self_test passed" in result.stdout


class TestConstants:
    def test_guard_event_count(self):
        assert len(mod.EVENT_CODES_GUARD) == 6

    def test_transition_event_count(self):
        assert len(mod.EVENT_CODES_TRANSITION) == 5

    def test_error_code_count(self):
        assert len(mod.ERROR_CODES) >= 6

    def test_invariant_count(self):
        assert len(mod.INVARIANTS) == 6


class TestIndividualChecks:
    @pytest.fixture(scope="class")
    def results(self):
        return {c["name"]: c for c in mod.run_all()["checks"]}

    def test_spec_exists(self, results):
        assert results["spec_exists"]["passed"]

    def test_guard_module_exists(self, results):
        assert results["guard_module_exists"]["passed"]

    def test_transition_module_exists(self, results):
        assert results["transition_module_exists"]["passed"]

    def test_runtime_wiring_guard(self, results):
        assert results["runtime_mod_wiring_guard"]["passed"]

    def test_runtime_wiring_transition(self, results):
        assert results["runtime_mod_wiring_transition"]["passed"]

    def test_fail_closed_path(self, results):
        assert results["fail_closed_unavailable_path"]["passed"]

    def test_fail_closed_latency_test(self, results):
        assert results["fail_closed_latency_test"]["passed"]

    def test_creation_epoch_private(self, results):
        assert results["artifact_creation_epoch_private"]["passed"]

    def test_creation_epoch_getter(self, results):
        assert results["artifact_creation_epoch_getter"]["passed"]

    def test_creation_epoch_no_setter(self, results):
        assert results["artifact_creation_epoch_no_setter"]["passed"]

    def test_key_integration(self, results):
        assert results["epoch_key_signing_integration"]["passed"]

    def test_transition_barrier_integration(self, results):
        assert results["transition_barrier_integration"]["passed"]

    def test_split_brain_guard(self, results):
        assert results["split_brain_guard"]["passed"]

    def test_transition_sequence(self, results):
        assert results["transition_sequence_apis"]["passed"]

    def test_abort_timeout_api(self, results):
        assert results["abort_timeout_api"]["passed"]

    def test_history_metadata(self, results):
        assert results["transition_history_metadata"]["passed"]

    def test_integration_five_services(self, results):
        assert results["integration_test_five_services"]["passed"]

    def test_integration_timeout_abort(self, results):
        assert results["integration_test_timeout_abort"]["passed"]

    def test_monotonicity_test(self, results):
        assert results["unit_test_monotonicity"]["passed"]

    def test_guard_test_count(self, results):
        assert results["guard_test_count"]["passed"]

    def test_transition_test_count(self, results):
        assert results["transition_test_count"]["passed"]


class TestOverall:
    def test_all_checks_pass(self):
        failed = [c for c in mod.run_all()["checks"] if not c["passed"]]
        assert len(failed) == 0, f"Failed checks: {[c['name'] for c in failed]}"

    def test_verdict_is_pass(self):
        result = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(result.stdout)
        assert data["verdict"] == "PASS"

    def test_human_output_contains_pass(self):
        result = subprocess.run([sys.executable, SCRIPT], capture_output=True, text=True)
        assert "bd-2gr" in result.stdout
        assert "PASS" in result.stdout
