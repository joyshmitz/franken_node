"""Unit tests for check_revocation_freshness.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestFreshnessFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/security/freshness_scenarios.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixture_has_cases(self):
        path = os.path.join(ROOT, "fixtures/security/freshness_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_allowed_and_denied(self):
        path = os.path.join(ROOT, "fixtures/security/freshness_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        allowed = [c for c in data["cases"] if c.get("expected_allowed") is True]
        denied = [c for c in data["cases"] if c.get("expected_allowed") is False]
        self.assertGreater(len(allowed), 0)
        self.assertGreater(len(denied), 0)


class TestFreshnessDecisions(unittest.TestCase):

    def test_decisions_exist(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1m8r/revocation_freshness_decisions.json")
        self.assertTrue(os.path.isfile(path))

    def test_decisions_valid(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1m8r/revocation_freshness_decisions.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("decisions", data)
        self.assertGreaterEqual(len(data["decisions"]), 3)

    def test_decisions_have_override(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1m8r/revocation_freshness_decisions.json")
        with open(path) as f:
            data = json.load(f)
        overrides = [d for d in data["decisions"] if d.get("override_receipt")]
        self.assertGreater(len(overrides), 0)


class TestFreshnessImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/security/revocation_freshness.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_safety_tier(self):
        self.assertIn("enum SafetyTier", self.content)

    def test_has_freshness_policy(self):
        self.assertIn("struct FreshnessPolicy", self.content)

    def test_has_freshness_decision(self):
        self.assertIn("struct FreshnessDecision", self.content)

    def test_has_freshness_error(self):
        self.assertIn("enum FreshnessError", self.content)

    def test_has_evaluate_freshness(self):
        self.assertIn("fn evaluate_freshness", self.content)

    def test_has_override_receipt(self):
        self.assertIn("struct OverrideReceipt", self.content)

    def test_has_all_error_codes(self):
        for code in ["RF_STALE_FRONTIER", "RF_OVERRIDE_REQUIRED", "RF_POLICY_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_all_tiers(self):
        for tier in ["Standard", "Risky", "Dangerous"]:
            self.assertIn(tier, self.content, f"Missing tier {tier}")


class TestFreshnessSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-1m8r_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-RF-TIER-GATE", "INV-RF-OVERRIDE-RECEIPT",
                    "INV-RF-STANDARD-PASS", "INV-RF-AUDIT"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["RF_STALE_FRONTIER", "RF_OVERRIDE_REQUIRED", "RF_POLICY_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestFreshnessSecurityTests(unittest.TestCase):

    def setUp(self):
        self.sec_path = os.path.join(ROOT, "tests/security/revocation_freshness_gate.rs")
        self.assertTrue(os.path.isfile(self.sec_path))
        with open(self.sec_path) as f:
            self.content = f.read()

    def test_covers_standard_pass(self):
        self.assertIn("inv_rf_standard", self.content)

    def test_covers_tier_gate(self):
        self.assertIn("inv_rf_tier_gate", self.content)

    def test_covers_override(self):
        self.assertIn("inv_rf_override", self.content)

    def test_covers_audit(self):
        self.assertIn("inv_rf_audit", self.content)


if __name__ == "__main__":
    unittest.main()
