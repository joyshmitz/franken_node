"""Unit tests for check_lease_service.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_lease_service.py"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-bq6y/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestLeaseFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = ROOT / "fixtures/lease/lease_scenarios.json"
        self.assertTrue(path.is_file())

    def test_fixture_has_cases(self):
        path = ROOT / "fixtures/lease/lease_scenarios.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_allowed_and_denied(self):
        path = ROOT / "fixtures/lease/lease_scenarios.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        allowed = [
            c for c in data["cases"]
            if isinstance(c.get("expected_allowed"), bool) and c["expected_allowed"]
        ]
        denied = [
            c for c in data["cases"]
            if isinstance(c.get("expected_allowed"), bool) and not c["expected_allowed"]
        ]
        self.assertGreater(len(allowed), 0)
        self.assertGreater(len(denied), 0)


class TestLeaseContract(unittest.TestCase):

    def test_contract_exists(self):
        path = ROOT / "artifacts/section_10_13/bd-bq6y/lease_service_contract.json"
        self.assertTrue(path.is_file())

    def test_contract_valid(self):
        path = ROOT / "artifacts/section_10_13/bd-bq6y/lease_service_contract.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("leases", data)
        self.assertGreaterEqual(len(data["leases"]), 2)

    def test_contract_has_decisions(self):
        path = ROOT / "artifacts/section_10_13/bd-bq6y/lease_service_contract.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("decisions", data)
        self.assertGreaterEqual(len(data["decisions"]), 2)


class TestLeaseImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/lease_service.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

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
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-bq6y_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-LS-EXPIRY", "INV-LS-RENEWAL",
                    "INV-LS-STALE-REJECT", "INV-LS-PURPOSE"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["LS_EXPIRED", "LS_STALE_USE", "LS_ALREADY_REVOKED", "LS_PURPOSE_MISMATCH"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestLeaseIntegrationTests(unittest.TestCase):

    def setUp(self):
        self.integ_path = ROOT / "tests/integration/lease_service_contract.rs"
        self.assertTrue(self.integ_path.is_file())
        self.content = self.integ_path.read_text(encoding="utf-8")

    def test_covers_expiry(self):
        self.assertIn("inv_ls_expiry", self.content)

    def test_covers_renewal(self):
        self.assertIn("inv_ls_renewal", self.content)

    def test_covers_stale(self):
        self.assertIn("inv_ls_stale", self.content)

    def test_covers_purpose(self):
        self.assertIn("inv_ls_purpose", self.content)


class TestLeaseCli(unittest.TestCase):

    def test_json_mode_is_structural_and_machine_readable(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        evidence = decode_json_object(result.stdout)
        statuses = {check["id"]: check["status"] for check in evidence["checks"]}

        self.assertEqual(evidence["gate"], "lease_service_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["LS-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-bq6y:", result.stdout)

    def test_json_mode_does_not_rewrite_evidence_artifact(self):
        before = EVIDENCE_PATH.read_text(encoding="utf-8")
        subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        after = EVIDENCE_PATH.read_text(encoding="utf-8")
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
