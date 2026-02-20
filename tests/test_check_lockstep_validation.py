#!/usr/bin/env python3
"""Unit tests for scripts/check_lockstep_validation.py (bd-1w78)."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_lockstep_validation.py"

# Import the module under test
sys.path.insert(0, str(ROOT / "scripts"))
import check_lockstep_validation as clv


class TestConstants(unittest.TestCase):
    """Verify module-level constants."""

    def test_bead_id(self):
        self.assertEqual(clv.BEAD_ID, "bd-1w78")

    def test_event_codes(self):
        self.assertEqual(clv.EVENT_CODES, ["CLV-001", "CLV-002", "CLV-003", "CLV-004"])

    def test_invariants(self):
        expected = [
            "INV-CLV-CONTINUOUS",
            "INV-CLV-COVERAGE",
            "INV-CLV-REGRESSION",
            "INV-CLV-CORPUS",
        ]
        self.assertEqual(clv.INVARIANTS, expected)

    def test_required_files_count(self):
        self.assertEqual(len(clv.REQUIRED_FILES), 4)


class TestCheckFunctions(unittest.TestCase):
    """Verify each check function returns the expected structure."""

    def _assert_check_structure(self, result):
        self.assertIsInstance(result, dict)
        self.assertIn("name", result)
        self.assertIn("passed", result)
        self.assertIn("detail", result)
        self.assertIsInstance(result["name"], str)
        self.assertIsInstance(result["passed"], bool)
        self.assertIsInstance(result["detail"], str)

    def test_check_files_exist(self):
        result = clv.check_files_exist()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "files_exist")

    def test_check_spec_completeness(self):
        result = clv.check_spec_completeness()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "spec_completeness")

    def test_check_lockstep_architecture(self):
        result = clv.check_lockstep_architecture()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "lockstep_architecture")

    def test_check_ci_integration(self):
        result = clv.check_ci_integration()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "ci_integration")

    def test_check_corpus_requirements(self):
        result = clv.check_corpus_requirements()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "corpus_requirements")

    def test_check_divergence_classification(self):
        result = clv.check_divergence_classification()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "divergence_classification")

    def test_check_event_codes(self):
        result = clv.check_event_codes()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "event_codes")

    def test_check_invariants(self):
        result = clv.check_invariants()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "invariants")

    def test_check_targets(self):
        result = clv.check_targets()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "targets")

    def test_check_alerting_policy(self):
        result = clv.check_alerting_policy()
        self._assert_check_structure(result)
        self.assertEqual(result["name"], "alerting_policy")


class TestRunAll(unittest.TestCase):
    """Verify the run_all() aggregation function."""

    def test_run_all_structure(self):
        result = clv.run_all()
        self.assertIn("bead_id", result)
        self.assertIn("passed", result)
        self.assertIn("total", result)
        self.assertIn("all_passed", result)
        self.assertIn("checks", result)

    def test_run_all_bead_id(self):
        result = clv.run_all()
        self.assertEqual(result["bead_id"], "bd-1w78")

    def test_run_all_counts(self):
        result = clv.run_all()
        self.assertEqual(result["total"], len(clv.ALL_CHECKS))
        self.assertGreaterEqual(result["passed"], 0)
        self.assertLessEqual(result["passed"], result["total"])

    def test_run_all_checks_list(self):
        result = clv.run_all()
        self.assertIsInstance(result["checks"], list)
        self.assertEqual(len(result["checks"]), len(clv.ALL_CHECKS))

    def test_all_passed_consistency(self):
        result = clv.run_all()
        self.assertEqual(result["all_passed"], result["passed"] == result["total"])


class TestJsonOutput(unittest.TestCase):
    """Verify the script produces valid JSON with --json flag."""

    def test_json_output(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Script may exit 0 or 1 depending on check results
        output = proc.stdout.strip()
        self.assertTrue(len(output) > 0, "no output produced")
        data = json.loads(output)
        self.assertEqual(data["bead_id"], "bd-1w78")
        self.assertIn("checks", data)


class TestSelfTest(unittest.TestCase):
    """Verify the built-in self_test() runs successfully."""

    def test_self_test_passes(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"self_test failed:\n{proc.stderr}")


if __name__ == "__main__":
    unittest.main()
