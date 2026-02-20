#!/usr/bin/env python3
"""Unit tests for scripts/check_strategic_foundations.py"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_strategic_foundations as checker


class TestFilesExist(unittest.TestCase):
    def test_two_files(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        checks = [r for r in checker.RESULTS if r["name"].startswith("file_exists:")]
        self.assertEqual(len(checks), 2)


class TestThreeKernel(unittest.TestCase):
    def test_three_kernels(self):
        checker.RESULTS.clear()
        checker.check_three_kernel()
        checks = [r for r in checker.RESULTS if r["name"].startswith("kernel:")]
        self.assertEqual(len(checks), 3)
        for r in checks:
            self.assertTrue(r["pass"], r["name"])


class TestFourPillars(unittest.TestCase):
    def test_four_pillars(self):
        checker.RESULTS.clear()
        checker.check_four_pillars()
        checks = [r for r in checker.RESULTS if r["name"].startswith("pillar:")]
        self.assertEqual(len(checks), 4)


class TestCoreProposition(unittest.TestCase):
    def test_three_propositions(self):
        checker.RESULTS.clear()
        checker.check_core_proposition()
        checks = [r for r in checker.RESULTS if r["name"].startswith("proposition:")]
        self.assertEqual(len(checks), 3)


class TestDisruptiveFloor(unittest.TestCase):
    def test_six_targets(self):
        checker.RESULTS.clear()
        checker.check_disruptive_floor()
        checks = [r for r in checker.RESULTS if r["name"].startswith("disruptive_floor:")]
        self.assertEqual(len(checks), 6)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_disruptive_floor()
        for r in checker.RESULTS:
            self.assertTrue(r["pass"], r["name"])


class TestCategoryDoctrine(unittest.TestCase):
    def test_five_rules(self):
        checker.RESULTS.clear()
        checker.check_category_doctrine()
        checks = [r for r in checker.RESULTS if r["name"].startswith("doctrine_rule:")]
        self.assertEqual(len(checks), 5)


class TestBuildStrategy(unittest.TestCase):
    def test_four_principles(self):
        checker.RESULTS.clear()
        checker.check_build_strategy()
        checks = [r for r in checker.RESULTS if r["name"].startswith("build_strategy:")]
        self.assertEqual(len(checks), 4)


class TestEventCodes(unittest.TestCase):
    def test_four_codes(self):
        checker.RESULTS.clear()
        checker.check_event_codes()
        checks = [r for r in checker.RESULTS if r["name"].startswith("event_code:")]
        self.assertEqual(len(checks), 4)


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
        self.assertEqual(result["bead_id"], "bd-3hyk")

    def test_math(self):
        result = checker.run_all()
        self.assertEqual(result["total"], result["passed"] + result["failed"])


class TestSelfTest(unittest.TestCase):
    def test_self_test(self):
        checker.self_test()


if __name__ == "__main__":
    unittest.main()
