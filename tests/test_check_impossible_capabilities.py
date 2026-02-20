#!/usr/bin/env python3
"""Unit tests for scripts/check_impossible_capabilities.py"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_impossible_capabilities as checker


class TestFilesExist(unittest.TestCase):
    def test_two_files(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        checks = [r for r in checker.RESULTS if r["name"].startswith("file_exists:")]
        self.assertEqual(len(checks), 2)


class TestTenCapabilities(unittest.TestCase):
    def test_ten_capabilities(self):
        checker.RESULTS.clear()
        checker.check_ten_capabilities()
        checks = [r for r in checker.RESULTS if r["name"].startswith("capability:")]
        self.assertEqual(len(checks), 10)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_ten_capabilities()
        for r in checker.RESULTS:
            self.assertTrue(r["pass"], r["name"])


class TestImpossibilityRationale(unittest.TestCase):
    def test_ten_rationales(self):
        checker.RESULTS.clear()
        checker.check_impossibility_rationale()
        self.assertTrue(checker.RESULTS[0]["pass"])


class TestOwnerTracks(unittest.TestCase):
    def test_thirteen_tracks(self):
        checker.RESULTS.clear()
        checker.check_owner_tracks()
        checks = [r for r in checker.RESULTS if r["name"].startswith("owner_track:")]
        self.assertEqual(len(checks), 13)


class TestCategoryTests(unittest.TestCase):
    def test_three_tests(self):
        checker.RESULTS.clear()
        checker.check_category_tests()
        checks = [r for r in checker.RESULTS if r["name"].startswith("category_test:")]
        self.assertEqual(len(checks), 3)


class TestQuantitativeTargets(unittest.TestCase):
    def test_five_targets(self):
        checker.RESULTS.clear()
        checker.check_quantitative_targets()
        checks = [r for r in checker.RESULTS if r["name"].startswith("target:")]
        self.assertEqual(len(checks), 5)


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
        self.assertEqual(result["bead_id"], "bd-2hrg")

    def test_math(self):
        result = checker.run_all()
        self.assertEqual(result["total"], result["passed"] + result["failed"])


class TestSelfTest(unittest.TestCase):
    def test_self_test(self):
        checker.self_test()


if __name__ == "__main__":
    unittest.main()
