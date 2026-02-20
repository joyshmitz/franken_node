#!/usr/bin/env python3
"""Unit tests for check_fencing.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_fencing as fc


class TestSpec(unittest.TestCase):
    def test_four_error_codes(self):
        self.assertEqual(len(fc.ERROR_CODES), 4)


class TestChecks(unittest.TestCase):
    def test_impl_passes(self):
        self.assertEqual(fc.check_impl()["status"], "PASS")

    def test_error_codes_passes(self):
        self.assertEqual(fc.check_error_codes()["status"], "PASS")

    def test_conformance_passes(self):
        self.assertEqual(fc.check_conformance()["status"], "PASS")

    def test_receipts_passes(self):
        self.assertEqual(fc.check_receipts()["status"], "PASS")

    def test_spec_passes(self):
        self.assertEqual(fc.check_spec()["status"], "PASS")


class TestSelfTest(unittest.TestCase):
    def test_verdict_pass(self):
        self.assertEqual(fc.self_test()["verdict"], "PASS")

    def test_no_failures(self):
        self.assertEqual(fc.self_test()["summary"]["failing_checks"], 0)

    def test_all_checks(self):
        self.assertGreaterEqual(fc.self_test()["summary"]["total_checks"], 6)


if __name__ == "__main__":
    unittest.main()
