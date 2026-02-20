#!/usr/bin/env python3
"""Unit tests for scripts/check_performance_doctrine.py"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_performance_doctrine as checker


class TestFilesExist(unittest.TestCase):
    def test_two_files(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        checks = [r for r in checker.RESULTS if r["name"].startswith("file_exists:")]
        self.assertEqual(len(checks), 2)
        for r in checks:
            self.assertTrue(r["pass"], r["name"])


class TestCorePrinciples(unittest.TestCase):
    def test_four_principles(self):
        checker.RESULTS.clear()
        checker.check_core_principles()
        checks = [r for r in checker.RESULTS if r["name"].startswith("principle:")]
        self.assertEqual(len(checks), 4)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_core_principles()
        for r in checker.RESULTS:
            self.assertTrue(r["pass"], r["name"])


class TestQuantitativeTargets(unittest.TestCase):
    def test_three_targets(self):
        checker.RESULTS.clear()
        checker.check_quantitative_targets()
        checks = [r for r in checker.RESULTS if r["name"].startswith("target:")]
        self.assertEqual(len(checks), 3)


class TestOptimizationLevers(unittest.TestCase):
    def test_five_levers(self):
        checker.RESULTS.clear()
        checker.check_optimization_levers()
        checks = [r for r in checker.RESULTS if r["name"].startswith("lever:")]
        self.assertEqual(len(checks), 5)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_optimization_levers()
        for r in checker.RESULTS:
            self.assertTrue(r["pass"], r["name"])


class TestLeverDetails(unittest.TestCase):
    def test_three_details(self):
        checker.RESULTS.clear()
        checker.check_lever_details()
        checks = [r for r in checker.RESULTS if r["name"].startswith("lever_detail:")]
        self.assertEqual(len(checks), 3)


class TestRequiredArtifacts(unittest.TestCase):
    def test_five_artifacts(self):
        checker.RESULTS.clear()
        checker.check_required_artifacts()
        checks = [r for r in checker.RESULTS if r["name"].startswith("artifact:")]
        self.assertEqual(len(checks), 5)


class TestArtifactContents(unittest.TestCase):
    def test_eight_keywords(self):
        checker.RESULTS.clear()
        checker.check_artifact_contents()
        checks = [r for r in checker.RESULTS if r["name"].startswith("artifact_content:")]
        self.assertEqual(len(checks), 8)


class TestImplementationMapping(unittest.TestCase):
    def test_three_tracks(self):
        checker.RESULTS.clear()
        checker.check_implementation_mapping()
        checks = [r for r in checker.RESULTS if r["name"].startswith("impl_mapping:")]
        self.assertEqual(len(checks), 3)


class TestEventCodes(unittest.TestCase):
    def test_five_codes(self):
        checker.RESULTS.clear()
        checker.check_event_codes()
        checks = [r for r in checker.RESULTS if r["name"].startswith("event_code:")]
        self.assertEqual(len(checks), 5)


class TestInvariants(unittest.TestCase):
    def test_four_invariants(self):
        checker.RESULTS.clear()
        checker.check_invariants()
        checks = [r for r in checker.RESULTS if r["name"].startswith("invariant:")]
        self.assertEqual(len(checks), 4)


class TestRunAll(unittest.TestCase):
    def test_returns_dict(self):
        result = checker.run_all()
        self.assertIsInstance(result, dict)

    def test_bead_id(self):
        result = checker.run_all()
        self.assertEqual(result["bead_id"], "bd-2vl5")

    def test_math(self):
        result = checker.run_all()
        self.assertEqual(result["total"], result["passed"] + result["failed"])


class TestSelfTest(unittest.TestCase):
    def test_self_test(self):
        checker.self_test()


if __name__ == "__main__":
    unittest.main()
