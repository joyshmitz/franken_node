"""Tests for scripts/check_section_10_10_plan_epic.py (bd-1hf)."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_section_10_10_plan_epic.py")

spec = importlib.util.spec_from_file_location("check_section_10_10_plan_epic", SCRIPT)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestConstants:
    def test_identity_constants(self):
        assert mod.BEAD_ID == "bd-1hf"
        assert mod.SECTION == "10.10"
        assert mod.SECTION_GATE_ID == "bd-1jjq"

    def test_impl_bead_count(self):
        assert len(mod.SECTION_IMPL_BEADS) == 11

    def test_impl_beads_unique(self):
        assert len(mod.SECTION_IMPL_BEADS) == len(set(mod.SECTION_IMPL_BEADS))


class TestJsonOutput:
    def test_cli_json_output(self):
        proc = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        data = json.loads(proc.stdout)
        assert data["bead_id"] == "bd-1hf"
        assert data["section"] == "10.10"
        assert isinstance(data["checks"], list)

    def test_cli_self_test(self):
        proc = subprocess.run([sys.executable, SCRIPT, "--self-test"], capture_output=True, text=True)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "self_test passed" in proc.stdout

    def test_verdict_field(self):
        proc = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        data = json.loads(proc.stdout)
        assert data["verdict"] in ("PASS", "FAIL")
        assert data["status"] in ("pass", "fail")


class TestRunAll:
    @pytest.fixture(scope="class")
    def result(self):
        return mod.run_all()

    @pytest.fixture(scope="class")
    def checks(self, result):
        return {entry["check"]: entry for entry in result["checks"]}

    def test_structure(self, result):
        for key in [
            "bead_id",
            "section",
            "title",
            "checks",
            "total",
            "passed",
            "failed",
            "overall_pass",
            "verdict",
            "status",
            "metrics",
        ]:
            assert key in result

    def test_verdict_is_pass(self, result):
        assert result["verdict"] == "PASS", json.dumps(result, indent=2)
        assert result["overall_pass"] is True
        assert result["failed"] == 0

    def test_required_checks_pass(self, checks):
        for name in [
            "epic_record_accessible",
            "epic_identity",
            "epic_section_label",
            "has_dependencies",
            "all_dependencies_closed",
            "section_gate_dependency_present",
            "master_graph_dependent_present",
            "section_gate_evidence_exists",
            "section_gate_evidence_parseable",
            "section_gate_verdict_pass",
            "section_contract_specs_present",
            "all_impl_evidence_present",
            "all_impl_summaries_present",
            "impl_beads_linked_to_epic_dependencies",
        ]:
            assert name in checks
            assert checks[name]["pass"], f"{name}: {checks[name]['detail']}"

    def test_metrics_are_coherent(self, result):
        metrics = result["metrics"]
        assert metrics["dependency_count"] >= 10
        assert metrics["dependency_count"] == metrics["dependency_closed_count"]
        assert metrics["section_contract_spec_count"] >= 11
        assert metrics["section_impl_bead_count"] == 11


class TestHelpers:
    def test_load_json_none_for_missing(self):
        missing_path = os.path.join(ROOT, "artifacts", "section_10_10", "bd-does-not-exist", "missing.json")
        assert mod._load_json(mod.Path(missing_path)) is None

    def test_evidence_pass_variants(self):
        assert mod._evidence_pass({"verdict": "PASS"})
        assert mod._evidence_pass({"overall_pass": True})
        assert mod._evidence_pass({"status": "completed_with_baseline_workspace_failures"})
        assert not mod._evidence_pass({"status": "fail"})

