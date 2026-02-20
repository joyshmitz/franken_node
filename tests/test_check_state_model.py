#!/usr/bin/env python3
"""Unit tests for check_state_model.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_state_model as sm


class TestSpec(unittest.TestCase):
    def test_four_model_types(self):
        self.assertEqual(len(sm.STATE_MODEL_TYPES), 4)

    def test_four_divergence_types(self):
        self.assertEqual(len(sm.DIVERGENCE_TYPES), 4)

    def test_four_error_codes(self):
        self.assertEqual(len(sm.ERROR_CODES), 4)


class TestChecks(unittest.TestCase):
    def test_impl_passes(self):
        self.assertEqual(sm.check_impl_exists()["status"], "PASS")

    def test_model_types_passes(self):
        self.assertEqual(sm.check_model_types()["status"], "PASS")

    def test_error_codes_passes(self):
        self.assertEqual(sm.check_error_codes()["status"], "PASS")

    def test_samples_passes(self):
        self.assertEqual(sm.check_samples()["status"], "PASS")

    def test_integration_passes(self):
        self.assertEqual(sm.check_integration_tests()["status"], "PASS")

    def test_spec_passes(self):
        self.assertEqual(sm.check_spec_document()["status"], "PASS")


class TestSelfTest(unittest.TestCase):
    def test_verdict_pass(self):
        self.assertEqual(sm.self_test()["verdict"], "PASS")

    def test_no_failures(self):
        self.assertEqual(sm.self_test()["summary"]["failing_checks"], 0)

    def test_all_checks_present(self):
        self.assertGreaterEqual(sm.self_test()["summary"]["total_checks"], 7)


if __name__ == "__main__":
    unittest.main()
