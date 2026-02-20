"""Unit tests for check_device_profile.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestDeviceProfileFixtures(unittest.TestCase):

    def test_fixtures_exist(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-8vby/device_profile_examples.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixtures_valid(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-8vby/device_profile_examples.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("profiles", data)
        self.assertGreaterEqual(len(data["profiles"]), 3)

    def test_fixtures_have_policies(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-8vby/device_profile_examples.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("policies", data)
        self.assertGreaterEqual(len(data["policies"]), 3)


class TestDeviceProfileImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/device_profile.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_device_profile(self):
        self.assertIn("struct DeviceProfile", self.content)

    def test_has_placement_constraint(self):
        self.assertIn("struct PlacementConstraint", self.content)

    def test_has_placement_policy(self):
        self.assertIn("struct PlacementPolicy", self.content)

    def test_has_placement_result(self):
        self.assertIn("struct PlacementResult", self.content)

    def test_has_device_profile_registry(self):
        self.assertIn("struct DeviceProfileRegistry", self.content)

    def test_has_validate_profile(self):
        self.assertIn("fn validate_profile", self.content)

    def test_has_evaluate_placement(self):
        self.assertIn("fn evaluate_placement", self.content)

    def test_has_all_error_codes(self):
        for code in ["DPR_SCHEMA_INVALID", "DPR_STALE_PROFILE",
                     "DPR_INVALID_CONSTRAINT", "DPR_NO_MATCH"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestDeviceProfileSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-8vby_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-DPR-SCHEMA", "INV-DPR-FRESHNESS",
                    "INV-DPR-DETERMINISTIC", "INV-DPR-REJECT-INVALID"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["DPR_SCHEMA_INVALID", "DPR_STALE_PROFILE",
                     "DPR_INVALID_CONSTRAINT", "DPR_NO_MATCH"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestDeviceProfileConformance(unittest.TestCase):

    def setUp(self):
        self.conf_path = os.path.join(ROOT, "tests/conformance/placement_policy_schema.rs")
        self.assertTrue(os.path.isfile(self.conf_path))
        with open(self.conf_path) as f:
            self.content = f.read()

    def test_covers_schema(self):
        self.assertIn("inv_dpr_schema", self.content)

    def test_covers_freshness(self):
        self.assertIn("inv_dpr_freshness", self.content)

    def test_covers_deterministic(self):
        self.assertIn("inv_dpr_deterministic", self.content)

    def test_covers_reject_invalid(self):
        self.assertIn("inv_dpr_reject_invalid", self.content)


if __name__ == "__main__":
    unittest.main()
