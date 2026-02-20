"""Unit tests for check_revocation_registry.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestRevocationFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/revocation/registry_scenarios.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixture_has_cases(self):
        path = os.path.join(ROOT, "fixtures/revocation/registry_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_stale_case(self):
        path = os.path.join(ROOT, "fixtures/revocation/registry_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        stale = [c for c in data["cases"] if c.get("expected_error_code") == "REV_STALE_HEAD"]
        self.assertGreater(len(stale), 0)


class TestRevocationHistory(unittest.TestCase):

    def test_history_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-y7lu/revocation_head_history.json")
        self.assertTrue(os.path.isfile(path))

    def test_history_valid(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-y7lu/revocation_head_history.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("zones", data)
        self.assertGreaterEqual(len(data["zones"]), 2)

    def test_history_has_stale_rejections(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-y7lu/revocation_head_history.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("stale_rejections", data)
        self.assertGreater(len(data["stale_rejections"]), 0)


class TestRevocationImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/supply_chain/revocation_registry.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_revocation_head(self):
        self.assertIn("struct RevocationHead", self.content)

    def test_has_revocation_registry(self):
        self.assertIn("struct RevocationRegistry", self.content)

    def test_has_revocation_error(self):
        self.assertIn("enum RevocationError", self.content)

    def test_has_advance_head(self):
        self.assertIn("fn advance_head", self.content)

    def test_has_recover(self):
        self.assertIn("fn recover_from_log", self.content)

    def test_has_is_revoked(self):
        self.assertIn("fn is_revoked", self.content)

    def test_has_all_error_codes(self):
        for code in ["REV_STALE_HEAD", "REV_ZONE_NOT_FOUND", "REV_RECOVERY_FAILED"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_audit(self):
        self.assertIn("struct RevocationAudit", self.content)


class TestRevocationSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-y7lu_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-REV-MONOTONIC", "INV-REV-STALE-REJECT",
                    "INV-REV-RECOVERABLE", "INV-REV-ZONE-ISOLATED"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["REV_STALE_HEAD", "REV_ZONE_NOT_FOUND", "REV_RECOVERY_FAILED"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestRevocationConformanceTests(unittest.TestCase):

    def setUp(self):
        self.conf_path = os.path.join(ROOT, "tests/conformance/revocation_head_monotonicity.rs")
        self.assertTrue(os.path.isfile(self.conf_path))
        with open(self.conf_path) as f:
            self.content = f.read()

    def test_covers_monotonic(self):
        self.assertIn("inv_rev_monotonic", self.content)

    def test_covers_stale(self):
        self.assertIn("inv_rev_stale", self.content)

    def test_covers_recoverable(self):
        self.assertIn("inv_rev_recoverable", self.content)

    def test_covers_isolated(self):
        self.assertIn("inv_rev_zone_isolated", self.content)


if __name__ == "__main__":
    unittest.main()
