#!/usr/bin/env python3
"""Unit tests for check_health_gate.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_health_gate as hg


class TestHealthGateSpec(unittest.TestCase):
    def test_three_required_checks(self):
        self.assertEqual(len(hg.REQUIRED_CHECKS), 3)

    def test_liveness_is_required(self):
        self.assertIn("liveness", hg.REQUIRED_CHECKS)

    def test_readiness_is_required(self):
        self.assertIn("readiness", hg.REQUIRED_CHECKS)

    def test_config_valid_is_required(self):
        self.assertIn("config_valid", hg.REQUIRED_CHECKS)

    def test_resource_ok_is_optional(self):
        self.assertIn("resource_ok", hg.OPTIONAL_CHECKS)

    def test_four_rollout_phases(self):
        self.assertEqual(len(hg.ROLLOUT_PHASES), 4)

    def test_four_error_codes(self):
        self.assertEqual(len(hg.ERROR_CODES), 4)


class TestCheckHealthGateSpec(unittest.TestCase):
    def test_passes(self):
        result = hg.check_health_gate_spec()
        self.assertEqual(result["status"], "PASS")


class TestCheckHealthGateImpl(unittest.TestCase):
    def test_passes(self):
        result = hg.check_health_gate_impl()
        self.assertEqual(result["status"], "PASS")


class TestCheckRolloutStateImpl(unittest.TestCase):
    def test_passes(self):
        result = hg.check_rollout_state_impl()
        self.assertEqual(result["status"], "PASS")


class TestCheckRolloutPhases(unittest.TestCase):
    def test_passes(self):
        result = hg.check_rollout_phases()
        self.assertEqual(result["status"], "PASS")


class TestCheckErrorCodes(unittest.TestCase):
    def test_passes(self):
        result = hg.check_error_codes()
        self.assertEqual(result["status"], "PASS")


class TestCheckReplayLog(unittest.TestCase):
    def test_passes(self):
        result = hg.check_replay_log()
        self.assertEqual(result["status"], "PASS")


class TestCheckSpecDocument(unittest.TestCase):
    def test_passes(self):
        result = hg.check_spec_document()
        self.assertEqual(result["status"], "PASS")


class TestCheckIntegrationTests(unittest.TestCase):
    def test_passes(self):
        result = hg.check_integration_tests()
        self.assertEqual(result["status"], "PASS")


class TestSelfTest(unittest.TestCase):
    def test_verdict_pass(self):
        result = hg.self_test()
        self.assertEqual(result["verdict"], "PASS")

    def test_all_checks_present(self):
        result = hg.self_test()
        self.assertGreaterEqual(result["summary"]["total_checks"], 9)

    def test_no_failures(self):
        result = hg.self_test()
        self.assertEqual(result["summary"]["failing_checks"], 0)


if __name__ == "__main__":
    unittest.main()
