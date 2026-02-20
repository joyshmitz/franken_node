"""Unit tests for check_lease_service.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestLeaseFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/lease/lease_scenarios.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixture_has_cases(self):
        path = os.path.join(ROOT, "fixtures/lease/lease_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_allowed_and_denied(self):
        path = os.path.join(ROOT, "fixtures/lease/lease_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        allowed = [c for c in data["cases"] if c.get("expected_allowed") is True]
        denied = [c for c in data["cases"] if c.get("expected_allowed") is False]
        self.assertGreater(len(allowed), 0)
        self.assertGreater(len(denied), 0)


class TestLeaseContract(unittest.TestCase):

    def test_contract_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-bq6y/lease_service_contract.json")
        self.assertTrue(os.path.isfile(path))

    def test_contract_valid(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-bq6y/lease_service_contract.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("leases", data)
        self.assertGreaterEqual(len(data["leases"]), 2)

    def test_contract_has_decisions(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-bq6y/lease_service_contract.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("decisions", data)
        self.assertGreaterEqual(len(data["decisions"]), 2)


class TestLeaseImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/lease_service.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_lease_purpose(self):
        self.assertIn("enum LeasePurpose", self.content)

    def test_has_lease(self):
        self.assertIn("struct Lease", self.content)

    def test_has_lease_service(self):
        self.assertIn("struct LeaseService", self.content)

    def test_has_lease_error(self):
        self.assertIn("enum LeaseError", self.content)

    def test_has_grant(self):
        self.assertIn("fn grant", self.content)

    def test_has_renew(self):
        self.assertIn("fn renew", self.content)

    def test_has_use_lease(self):
        self.assertIn("fn use_lease", self.content)

    def test_has_all_purposes(self):
        for p in ["Operation", "StateWrite", "MigrationHandoff"]:
            self.assertIn(p, self.content, f"Missing purpose {p}")

    def test_has_all_error_codes(self):
        for code in ["LS_EXPIRED", "LS_STALE_USE", "LS_ALREADY_REVOKED", "LS_PURPOSE_MISMATCH"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestLeaseSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-bq6y_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-LS-EXPIRY", "INV-LS-RENEWAL",
                    "INV-LS-STALE-REJECT", "INV-LS-PURPOSE"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["LS_EXPIRED", "LS_STALE_USE", "LS_ALREADY_REVOKED", "LS_PURPOSE_MISMATCH"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestLeaseIntegrationTests(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/lease_service_contract.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_expiry(self):
        self.assertIn("inv_ls_expiry", self.content)

    def test_covers_renewal(self):
        self.assertIn("inv_ls_renewal", self.content)

    def test_covers_stale(self):
        self.assertIn("inv_ls_stale", self.content)

    def test_covers_purpose(self):
        self.assertIn("inv_ls_purpose", self.content)


if __name__ == "__main__":
    unittest.main()
