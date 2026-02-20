#!/usr/bin/env python3
"""Unit tests for scripts/check_architecture_blueprint.py"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_architecture_blueprint as checker


class TestFilesExist(unittest.TestCase):
    def test_two_files(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        checks = [r for r in checker.RESULTS if r["name"].startswith("file_exists:")]
        self.assertEqual(len(checks), 2)


class TestThreeKernels(unittest.TestCase):
    def test_three_kernels(self):
        checker.RESULTS.clear()
        checker.check_three_kernels()
        checks = [r for r in checker.RESULTS if r["name"].startswith("kernel:")]
        self.assertEqual(len(checks), 3)


class TestProductPlanes(unittest.TestCase):
    def test_five_planes(self):
        checker.RESULTS.clear()
        checker.check_product_planes()
        checks = [r for r in checker.RESULTS if r["name"].startswith("product_plane:")]
        self.assertEqual(len(checks), 5)


class TestControlPlanes(unittest.TestCase):
    def test_three_planes(self):
        checker.RESULTS.clear()
        checker.check_control_planes()
        checks = [r for r in checker.RESULTS if r["name"].startswith("control_plane:")]
        self.assertEqual(len(checks), 3)


class TestTenInvariants(unittest.TestCase):
    def test_ten_invariants(self):
        checker.RESULTS.clear()
        checker.check_ten_invariants()
        checks = [r for r in checker.RESULTS if r["name"].startswith("hri:")]
        self.assertEqual(len(checks), 10)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_ten_invariants()
        for r in checker.RESULTS:
            self.assertTrue(r["pass"], r["name"])


class TestAlignmentContracts(unittest.TestCase):
    def test_five_contracts(self):
        checker.RESULTS.clear()
        checker.check_alignment_contracts()
        checks = [r for r in checker.RESULTS if r["name"].startswith("alignment:")]
        self.assertEqual(len(checks), 5)


class TestBoundaryRules(unittest.TestCase):
    def test_boundary_keywords(self):
        checker.RESULTS.clear()
        checker.check_boundary_rules()
        checks = [r for r in checker.RESULTS if r["name"].startswith("boundary:")]
        self.assertEqual(len(checks), 3)


class TestEventCodes(unittest.TestCase):
    def test_four_codes(self):
        checker.RESULTS.clear()
        checker.check_event_codes()
        checks = [r for r in checker.RESULTS if r["name"].startswith("event_code:")]
        self.assertEqual(len(checks), 4)


class TestRunAll(unittest.TestCase):
    def test_returns_dict(self):
        result = checker.run_all()
        self.assertIsInstance(result, dict)

    def test_bead_id(self):
        result = checker.run_all()
        self.assertEqual(result["bead_id"], "bd-k25j")

    def test_math(self):
        result = checker.run_all()
        self.assertEqual(result["total"], result["passed"] + result["failed"])


class TestSelfTest(unittest.TestCase):
    def test_self_test(self):
        checker.self_test()


if __name__ == "__main__":
    unittest.main()
