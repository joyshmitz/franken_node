"""Unit tests for check_anti_amplification.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestAntiAmplificationReport(unittest.TestCase):

    def test_report_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3b8m/anti_amplification_test_results.json")
        self.assertTrue(os.path.isfile(path))

    def test_report_valid_json(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3b8m/anti_amplification_test_results.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("scenarios", data)
        self.assertGreaterEqual(len(data["scenarios"]), 3)

    def test_report_has_block_scenarios(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3b8m/anti_amplification_test_results.json")
        with open(path) as f:
            data = json.load(f)
        verdicts = [s.get("verdict") for s in data["scenarios"]]
        self.assertIn("BLOCK", verdicts)


class TestAntiAmplificationImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/anti_amplification.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_amplification_policy(self):
        self.assertIn("struct AmplificationPolicy", self.content)

    def test_has_response_bound(self):
        self.assertIn("struct ResponseBound", self.content)

    def test_has_bound_check_request(self):
        self.assertIn("struct BoundCheckRequest", self.content)

    def test_has_bound_check_verdict(self):
        self.assertIn("struct BoundCheckVerdict", self.content)

    def test_has_check_function(self):
        self.assertIn("fn check_response_bound", self.content)

    def test_has_harness_function(self):
        self.assertIn("fn run_adversarial_harness", self.content)

    def test_has_all_error_codes(self):
        for code in ["AAR_RESPONSE_TOO_LARGE", "AAR_RATIO_EXCEEDED", "AAR_UNAUTH_LIMIT",
                     "AAR_ITEMS_EXCEEDED", "AAR_INVALID_POLICY"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestAntiAmplificationSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-3b8m_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-AAR-BOUNDED", "INV-AAR-UNAUTH-STRICT",
                    "INV-AAR-AUDITABLE", "INV-AAR-DETERMINISTIC"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["AAR_RESPONSE_TOO_LARGE", "AAR_RATIO_EXCEEDED", "AAR_UNAUTH_LIMIT",
                     "AAR_ITEMS_EXCEEDED", "AAR_INVALID_POLICY"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestAntiAmplificationIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/anti_amplification_harness.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_bounded(self):
        self.assertIn("inv_aar_bounded", self.content)

    def test_covers_unauth_strict(self):
        self.assertIn("inv_aar_unauth_strict", self.content)

    def test_covers_auditable(self):
        self.assertIn("inv_aar_auditable", self.content)

    def test_covers_deterministic(self):
        self.assertIn("inv_aar_deterministic", self.content)


if __name__ == "__main__":
    unittest.main()
