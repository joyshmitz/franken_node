#!/usr/bin/env python3
"""Unit tests for scripts/check_friction_pathway.py (bd-34d5)."""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_friction_pathway as cfp


class TestCheckFrictionPathway(unittest.TestCase):
    """Tests for each verification check."""

    # ------------------------------------------------------------------
    # Structural self-test
    # ------------------------------------------------------------------
    def test_self_test(self):
        """self_test() must not raise."""
        cfp.self_test()

    # ------------------------------------------------------------------
    # File-existence checks
    # ------------------------------------------------------------------
    def test_spec_exists(self):
        result = cfp.check_spec_exists()
        self.assertIn("check", result)
        self.assertEqual(result["check"], "spec_exists")
        self.assertIsInstance(result["passed"], bool)
        self.assertTrue(result["passed"], "Spec file should exist")

    def test_policy_exists(self):
        result = cfp.check_policy_exists()
        self.assertEqual(result["check"], "policy_exists")
        self.assertTrue(result["passed"], "Policy file should exist")

    # ------------------------------------------------------------------
    # Archetype checks
    # ------------------------------------------------------------------
    def test_archetypes_defined(self):
        result = cfp.check_archetypes()
        self.assertEqual(result["check"], "archetypes_defined")
        self.assertTrue(result["passed"], result["detail"])

    def test_archetype_scores(self):
        result = cfp.check_archetype_scores()
        self.assertEqual(result["check"], "archetype_scores")
        self.assertTrue(result["passed"], result["detail"])

    # ------------------------------------------------------------------
    # Time budget
    # ------------------------------------------------------------------
    def test_time_budget(self):
        result = cfp.check_time_budget()
        self.assertEqual(result["check"], "time_budget")
        self.assertTrue(result["passed"], result["detail"])

    # ------------------------------------------------------------------
    # Zero-edit requirement
    # ------------------------------------------------------------------
    def test_zero_edit(self):
        result = cfp.check_zero_edit()
        self.assertEqual(result["check"], "zero_edit_requirement")
        self.assertTrue(result["passed"], result["detail"])

    # ------------------------------------------------------------------
    # Event codes
    # ------------------------------------------------------------------
    def test_event_codes(self):
        result = cfp.check_event_codes()
        self.assertEqual(result["check"], "event_codes")
        self.assertTrue(result["passed"], result["detail"])

    # ------------------------------------------------------------------
    # Invariants
    # ------------------------------------------------------------------
    def test_invariants(self):
        result = cfp.check_invariants()
        self.assertEqual(result["check"], "invariants")
        self.assertTrue(result["passed"], result["detail"])

    # ------------------------------------------------------------------
    # Policy content checks
    # ------------------------------------------------------------------
    def test_telemetry_in_policy(self):
        result = cfp.check_telemetry_in_policy()
        self.assertEqual(result["check"], "telemetry_policy")
        self.assertTrue(result["passed"], result["detail"])

    def test_error_handling_policy(self):
        result = cfp.check_error_handling_policy()
        self.assertEqual(result["check"], "error_handling_policy")
        self.assertTrue(result["passed"], result["detail"])

    def test_ci_gate_policy(self):
        result = cfp.check_ci_gate_policy()
        self.assertEqual(result["check"], "ci_gate_policy")
        self.assertTrue(result["passed"], result["detail"])

    def test_spec_sections(self):
        result = cfp.check_spec_sections()
        self.assertEqual(result["check"], "spec_sections")
        self.assertTrue(result["passed"], result["detail"])

    def test_policy_pathway_steps(self):
        result = cfp.check_policy_pathway_steps()
        self.assertEqual(result["check"], "policy_pathway_steps")
        self.assertTrue(result["passed"], result["detail"])

    # ------------------------------------------------------------------
    # Aggregate run
    # ------------------------------------------------------------------
    def test_run_all_checks_count(self):
        results = cfp.run_all_checks()
        self.assertEqual(len(results), len(cfp.ALL_CHECKS))

    def test_run_all_checks_pass(self):
        results = cfp.run_all_checks()
        for r in results:
            self.assertTrue(r["passed"], f"Check '{r['check']}' failed: {r['detail']}")

    # ------------------------------------------------------------------
    # Evidence and summary generation
    # ------------------------------------------------------------------
    def test_write_evidence(self):
        results = cfp.run_all_checks()
        cfp.write_evidence(results)
        self.assertTrue(cfp.EVIDENCE_PATH.is_file(), "Evidence file should be written")
        data = json.loads(cfp.EVIDENCE_PATH.read_text())
        self.assertEqual(data["bead_id"], "bd-34d5")
        self.assertEqual(data["total_checks"], len(results))
        self.assertIn("checks", data)

    def test_write_summary(self):
        results = cfp.run_all_checks()
        cfp.write_summary(results)
        self.assertTrue(cfp.SUMMARY_PATH.is_file(), "Summary file should be written")
        content = cfp.SUMMARY_PATH.read_text()
        self.assertIn("bd-34d5", content)
        self.assertIn("PASS", content)

    # ------------------------------------------------------------------
    # CLI --json output
    # ------------------------------------------------------------------
    def test_cli_json_output(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_friction_pathway.py"), "--json"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        self.assertEqual(result.returncode, 0, f"Script failed: {result.stderr}")
        data = json.loads(result.stdout)
        self.assertEqual(data["bead_id"], "bd-34d5")
        self.assertTrue(data["all_passed"])

    def test_cli_human_output(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_friction_pathway.py")],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        self.assertEqual(result.returncode, 0, f"Script failed: {result.stderr}")
        self.assertIn("bd-34d5", result.stdout)
        self.assertIn("PASS", result.stdout)

    # ------------------------------------------------------------------
    # Missing-file edge cases (mock Path.is_file to return False)
    # ------------------------------------------------------------------
    def test_spec_missing_graceful(self):
        with patch.object(cfp, "SPEC_PATH", Path("/nonexistent/spec.md")):
            result = cfp.check_spec_exists()
            self.assertFalse(result["passed"])

    def test_policy_missing_graceful(self):
        with patch.object(cfp, "POLICY_PATH", Path("/nonexistent/policy.md")):
            result = cfp.check_policy_exists()
            self.assertFalse(result["passed"])

    def test_archetypes_missing_spec_graceful(self):
        with patch.object(cfp, "SPEC_PATH", Path("/nonexistent/spec.md")):
            result = cfp.check_archetypes()
            self.assertFalse(result["passed"])
            self.assertIn("missing", result["detail"].lower())

    def test_event_codes_missing_spec_graceful(self):
        with patch.object(cfp, "SPEC_PATH", Path("/nonexistent/spec.md")):
            result = cfp.check_event_codes()
            self.assertFalse(result["passed"])

    def test_invariants_missing_spec_graceful(self):
        with patch.object(cfp, "SPEC_PATH", Path("/nonexistent/spec.md")):
            result = cfp.check_invariants()
            self.assertFalse(result["passed"])

    def test_telemetry_missing_policy_graceful(self):
        with patch.object(cfp, "POLICY_PATH", Path("/nonexistent/policy.md")):
            result = cfp.check_telemetry_in_policy()
            self.assertFalse(result["passed"])

    def test_error_handling_missing_policy_graceful(self):
        with patch.object(cfp, "POLICY_PATH", Path("/nonexistent/policy.md")):
            result = cfp.check_error_handling_policy()
            self.assertFalse(result["passed"])


if __name__ == "__main__":
    unittest.main()
