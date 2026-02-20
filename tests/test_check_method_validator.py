#!/usr/bin/env python3
"""Unit tests for check_method_validator.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_method_validator as mv


class TestMethodSpec(unittest.TestCase):
    def test_nine_standard_methods(self):
        self.assertEqual(len(mv.STANDARD_METHODS), 9)

    def test_eight_required_methods(self):
        self.assertEqual(len(mv.REQUIRED_METHODS), 8)

    def test_simulate_is_optional(self):
        self.assertNotIn("simulate", mv.REQUIRED_METHODS)
        self.assertIn("simulate", mv.STANDARD_METHODS)

    def test_four_error_codes(self):
        self.assertEqual(len(mv.ERROR_CODES), 4)

    def test_handshake_required(self):
        self.assertIn("handshake", mv.REQUIRED_METHODS)

    def test_shutdown_required(self):
        self.assertIn("shutdown", mv.REQUIRED_METHODS)


class TestCheckMethodCount(unittest.TestCase):
    def test_passes(self):
        self.assertEqual(mv.check_method_count()["status"], "PASS")


class TestCheckRequiredCount(unittest.TestCase):
    def test_passes(self):
        self.assertEqual(mv.check_required_count()["status"], "PASS")


class TestCheckImplExists(unittest.TestCase):
    def test_passes(self):
        self.assertEqual(mv.check_impl_exists()["status"], "PASS")


class TestCheckErrorCodes(unittest.TestCase):
    def test_passes(self):
        self.assertEqual(mv.check_error_codes_impl()["status"], "PASS")


class TestCheckContractReport(unittest.TestCase):
    def test_passes(self):
        self.assertEqual(mv.check_contract_report()["status"], "PASS")


class TestCheckSpec(unittest.TestCase):
    def test_passes(self):
        self.assertEqual(mv.check_spec_document()["status"], "PASS")


class TestCheckCoverage(unittest.TestCase):
    def test_passes(self):
        self.assertEqual(mv.check_all_methods_in_impl()["status"], "PASS")


class TestSelfTest(unittest.TestCase):
    def test_verdict_pass(self):
        result = mv.self_test()
        self.assertEqual(result["verdict"], "PASS")

    def test_all_checks_present(self):
        result = mv.self_test()
        self.assertGreaterEqual(result["summary"]["total_checks"], 8)

    def test_no_failures(self):
        result = mv.self_test()
        self.assertEqual(result["summary"]["failing_checks"], 0)


if __name__ == "__main__":
    unittest.main()
