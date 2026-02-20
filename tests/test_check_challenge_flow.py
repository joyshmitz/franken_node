"""Unit tests for check_challenge_flow.py verification script (bd-29yx)."""

import importlib.util
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

spec = importlib.util.spec_from_file_location(
    "check_challenge_flow",
    ROOT + "/scripts/check_challenge_flow.py",
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestRunChecks:
    def test_returns_list(self):
        result = mod.run_checks()
        assert isinstance(result, list)

    def test_all_entries_have_required_keys(self):
        for entry in mod.run_checks():
            assert "check" in entry
            assert "pass" in entry
            assert "detail" in entry

    def test_pass_values_are_bool(self):
        for entry in mod.run_checks():
            assert isinstance(entry["pass"], bool)

    def test_minimum_check_count(self):
        result = mod.run_checks()
        assert len(result) >= 90, f"Expected >= 90 checks, got {len(result)}"

    def test_all_checks_pass(self):
        result = mod.run_checks()
        failing = [c for c in result if not c["pass"]]
        assert not failing, f"Failing checks: {failing}"


class TestFileChecks:
    def test_implementation_file(self):
        checks = mod.run_checks()
        assert next(c for c in checks if c["check"] == "file: implementation")["pass"]

    def test_spec_file(self):
        checks = mod.run_checks()
        assert next(c for c in checks if c["check"] == "file: spec contract")["pass"]

    def test_transcript_file(self):
        checks = mod.run_checks()
        assert next(c for c in checks if c["check"] == "file: challenge transcript artifact")["pass"]


class TestTypeChecks:
    TYPES = [
        "pub struct ChallengeId",
        "pub struct ArtifactId",
        "pub enum SuspicionReason",
        "pub enum RequiredProofType",
        "pub enum ChallengeState",
        "pub struct ProofSubmission",
        "pub struct ChallengeConfig",
        "pub struct ChallengeAuditEntry",
        "pub struct ChallengeError",
        "pub struct ChallengeMetrics",
        "pub struct Challenge",
        "pub struct ChallengeFlowController",
    ]

    @pytest.mark.parametrize("ty", TYPES)
    def test_type_found(self, ty):
        checks = mod.run_checks()
        check = next(c for c in checks if c["check"] == f"type: {ty}")
        assert check["pass"], f"Type not found: {ty}"


class TestEventCodes:
    CODES = [
        "CHALLENGE_ISSUED", "CHALLENGE_PROOF_RECEIVED", "CHALLENGE_VERIFIED",
        "CHALLENGE_TIMED_OUT", "CHALLENGE_DENIED", "CHALLENGE_PROMOTED",
    ]

    @pytest.mark.parametrize("code", CODES)
    def test_event_code_found(self, code):
        checks = mod.run_checks()
        check = next(c for c in checks if c["check"] == f"event_code: {code}")
        assert check["pass"]


class TestInvariants:
    INVARIANTS = [
        "INV-CHALLENGE-DEFER",
        "INV-CHALLENGE-TIMEOUT-DENY",
        "INV-CHALLENGE-AUDIT",
        "INV-CHALLENGE-VALID-TRANSITIONS",
    ]

    @pytest.mark.parametrize("inv", INVARIANTS)
    def test_invariant_found(self, inv):
        checks = mod.run_checks()
        check = next(c for c in checks if c["check"] == f"invariant: {inv}")
        assert check["pass"]


class TestUnitTestCount:
    def test_count_passes(self):
        checks = mod.run_checks()
        check = next(c for c in checks if c["check"] == "unit test count")
        assert check["pass"]


class TestSelfTest:
    def test_self_test_passes(self):
        assert mod.self_test()


class TestCheckHelper:
    def test_pass_true(self):
        result = mod._check("t", True, "ok")
        assert result["pass"] is True

    def test_pass_false(self):
        result = mod._check("t", False)
        assert result["detail"] == "NOT FOUND"


class TestJsonOutput:
    def test_cli_json(self):
        result = subprocess.run(
            [sys.executable, ROOT + "/scripts/check_challenge_flow.py", "--json"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["verdict"] == "PASS"
