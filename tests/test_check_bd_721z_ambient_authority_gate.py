"""Tests for scripts/check_bd_721z_ambient_authority_gate.py (bd-721z)."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "check_bd_721z_ambient_authority_gate.py")

spec = importlib.util.spec_from_file_location("check_bd_721z_ambient_authority_gate", SCRIPT)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test() is True


class TestConstants:
    def test_identity_constants(self):
        assert mod.BEAD_ID == "bd-721z"
        assert mod.SECTION == "10.15"

    def test_event_codes(self):
        assert mod.EXPECTED_EVENT_CODES == ["AMB-001", "AMB-002", "AMB-003", "AMB-004"]

    def test_restricted_api_markers_count(self):
        assert len(mod.EXPECTED_RESTRICTED_APIS) >= 10


class TestJsonOutput:
    def test_cli_json_output(self):
        proc = subprocess.run([sys.executable, SCRIPT, "--json"], capture_output=True, text=True)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        data = json.loads(proc.stdout)
        assert data["bead_id"] == "bd-721z"
        assert data["section"] == "10.15"
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
            "bead_record_accessible",
            "bead_identity",
            "section_label_present",
            "not_blocked",
            "downstream_gate_linked",
            "required_artifacts_exist",
            "gate_event_codes_present",
            "gate_restricted_apis_present",
            "policy_event_codes_documented",
            "allowlist_parseable",
            "allowlist_entries_present",
            "allowlist_signatures_valid",
            "allowlist_entries_not_expired",
            "findings_parseable",
            "evidence_parseable",
            "findings_no_violations",
            "findings_allowlist_integrity",
            "evidence_status_pass",
            "findings_evidence_metrics_match",
            "summary_reports_pass",
        ]:
            assert name in checks
            assert checks[name]["pass"], f"{name}: {checks[name]['detail']}"

    def test_metrics_are_coherent(self, result):
        metrics = result["metrics"]
        assert metrics["allowlist_entries"] >= 1
        assert metrics["dependent_count"] >= 1
        assert metrics["event_codes_required"] == 4
        assert metrics["restricted_api_markers_required"] >= 10


class TestHelpers:
    def test_load_json_none_for_missing(self):
        missing_path = os.path.join(ROOT, "artifacts", "section_10_15", "bd-nope", "missing.json")
        assert mod._load_json(mod.Path(missing_path)) is None

    def test_signature_computation_prefix(self):
        entry = {
            "module_path": "a.rs",
            "ambient_api": "std::net",
            "justification": "test",
            "signer": "tester",
            "expires_on": "2026-12-31",
        }
        sig = mod._compute_allowlist_signature(entry)
        assert sig.startswith("sha256:")

    def test_evidence_pass_variants(self):
        assert mod._evidence_pass({"status": "pass"})
        assert mod._evidence_pass({"verdict": "PASS"})
        assert not mod._evidence_pass({"status": "fail"})
