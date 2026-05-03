"""Unit tests for check_revocation_registry.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_revocation_registry.py"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-y7lu/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestRevocationFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = ROOT / "fixtures/revocation/registry_scenarios.json"
        self.assertTrue(path.is_file())

    def test_fixture_has_cases(self):
        path = ROOT / "fixtures/revocation/registry_scenarios.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_stale_case(self):
        path = ROOT / "fixtures/revocation/registry_scenarios.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        stale = [c for c in data["cases"] if c.get("expected_error_code") == "REV_STALE_HEAD"]
        self.assertGreater(len(stale), 0)


class TestRevocationHistory(unittest.TestCase):

    def test_history_exists(self):
        path = ROOT / "artifacts/section_10_13/bd-y7lu/revocation_head_history.json"
        self.assertTrue(path.is_file())

    def test_history_valid(self):
        path = ROOT / "artifacts/section_10_13/bd-y7lu/revocation_head_history.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("zones", data)
        self.assertGreaterEqual(len(data["zones"]), 2)

    def test_history_has_stale_rejections(self):
        path = ROOT / "artifacts/section_10_13/bd-y7lu/revocation_head_history.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("stale_rejections", data)
        self.assertGreater(len(data["stale_rejections"]), 0)


class TestRevocationImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/supply_chain/revocation_registry.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

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
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-y7lu_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-REV-MONOTONIC", "INV-REV-STALE-REJECT",
                    "INV-REV-RECOVERABLE", "INV-REV-ZONE-ISOLATED"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["REV_STALE_HEAD", "REV_ZONE_NOT_FOUND", "REV_RECOVERY_FAILED"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestRevocationConformanceTests(unittest.TestCase):

    def setUp(self):
        self.conf_path = ROOT / "tests/conformance/revocation_head_monotonicity.rs"
        self.assertTrue(self.conf_path.is_file())
        self.content = self.conf_path.read_text(encoding="utf-8")

    def test_covers_monotonic(self):
        self.assertIn("inv_rev_monotonic", self.content)

    def test_covers_stale(self):
        self.assertIn("inv_rev_stale", self.content)

    def test_covers_recoverable(self):
        self.assertIn("inv_rev_recoverable", self.content)

    def test_covers_isolated(self):
        self.assertIn("inv_rev_zone_isolated", self.content)


class TestRevocationCli(unittest.TestCase):

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

        self.assertEqual(evidence["gate"], "revocation_registry_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["RR-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-y7lu:", result.stdout)

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
