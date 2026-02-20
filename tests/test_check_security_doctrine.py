#!/usr/bin/env python3
"""Unit tests for scripts/check_security_doctrine.py"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_security_doctrine as checker


class TestFilesExist(unittest.TestCase):
    def test_two_files(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        checks = [r for r in checker.RESULTS if r["name"].startswith("file_exists:")]
        self.assertEqual(len(checks), 2)
        for r in checks:
            self.assertTrue(r["pass"], r["name"])


class TestAdversaryClasses(unittest.TestCase):
    def test_five_classes(self):
        checker.RESULTS.clear()
        checker.check_adversary_classes()
        checks = [r for r in checker.RESULTS if r["name"].startswith("adversary:")]
        self.assertEqual(len(checks), 5)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_adversary_classes()
        for r in checker.RESULTS:
            if r["name"].startswith("adversary:"):
                self.assertTrue(r["pass"], r["name"])


class TestMitigations(unittest.TestCase):
    def test_mitigation_keywords(self):
        checker.RESULTS.clear()
        checker.check_adversary_mitigations()
        checks = [r for r in checker.RESULTS if r["name"].startswith("mitigation:")]
        self.assertEqual(len(checks), 9)


class TestTrustSurfaces(unittest.TestCase):
    def test_five_surfaces(self):
        checker.RESULTS.clear()
        checker.check_trust_surfaces()
        checks = [r for r in checker.RESULTS if r["name"].startswith("surface:")]
        self.assertEqual(len(checks), 5)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_trust_surfaces()
        for r in checker.RESULTS:
            if r["name"].startswith("surface:"):
                self.assertTrue(r["pass"], r["name"])


class TestSafetyTargets(unittest.TestCase):
    def test_four_targets(self):
        checker.RESULTS.clear()
        checker.check_safety_targets()
        checks = [r for r in checker.RESULTS if r["name"].startswith("safety_target:")]
        self.assertEqual(len(checks), 4)


class TestThresholds(unittest.TestCase):
    def test_three_thresholds(self):
        checker.RESULTS.clear()
        checker.check_quantitative_thresholds()
        checks = [r for r in checker.RESULTS if r["name"].startswith("threshold:")]
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


class TestCrossSectionMapping(unittest.TestCase):
    def test_eight_sections(self):
        checker.RESULTS.clear()
        checker.check_cross_section_mapping()
        checks = [r for r in checker.RESULTS if r["name"].startswith("cross_section:")]
        self.assertEqual(len(checks), 8)


class TestRequiredSections(unittest.TestCase):
    def test_six_sections(self):
        checker.RESULTS.clear()
        checker.check_required_sections()
        checks = [r for r in checker.RESULTS if r["name"].startswith("section:")]
        self.assertEqual(len(checks), 6)


class TestSpecContract(unittest.TestCase):
    def test_spec_keywords(self):
        checker.RESULTS.clear()
        checker.check_spec_contract()
        checks = [r for r in checker.RESULTS if r["name"].startswith("spec:")]
        self.assertEqual(len(checks), 6)


class TestRunAll(unittest.TestCase):
    def test_returns_dict(self):
        result = checker.run_all()
        self.assertIsInstance(result, dict)

    def test_required_keys(self):
        result = checker.run_all()
        for key in ["bead_id", "verdict", "total", "passed", "failed", "checks"]:
            self.assertIn(key, result)

    def test_bead_id(self):
        result = checker.run_all()
        self.assertEqual(result["bead_id"], "bd-ud5h")

    def test_math(self):
        result = checker.run_all()
        self.assertEqual(result["total"], result["passed"] + result["failed"])


class TestSelfTest(unittest.TestCase):
    def test_self_test(self):
        checker.self_test()


if __name__ == "__main__":
    unittest.main()
