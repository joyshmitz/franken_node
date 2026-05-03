"""Unit tests for check_quarantine_promotion.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_quarantine_promotion.py"
RECEIPTS_PATH = ROOT / "artifacts/section_10_13/bd-3cm3/quarantine_promotion_receipts.json"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-3cm3/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestPromotionReceipts(unittest.TestCase):

    def test_receipts_exist(self):
        self.assertTrue(RECEIPTS_PATH.is_file())

    def test_receipts_valid_json(self):
        data = decode_json_object(RECEIPTS_PATH.read_text(encoding="utf-8"))
        self.assertIn("receipts", data)
        self.assertGreaterEqual(len(data["receipts"]), 1)

    def test_has_rejections(self):
        data = decode_json_object(RECEIPTS_PATH.read_text(encoding="utf-8"))
        self.assertIn("rejections", data)
        self.assertGreaterEqual(len(data["rejections"]), 1)


class TestPromotionImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/quarantine_promotion.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_promotion_rule(self):
        self.assertIn("struct PromotionRule", self.content)

    def test_has_promotion_request(self):
        self.assertIn("struct PromotionRequest", self.content)

    def test_has_provenance_receipt(self):
        self.assertIn("struct ProvenanceReceipt", self.content)

    def test_has_promotion_result(self):
        self.assertIn("struct PromotionResult", self.content)

    def test_has_evaluate_promotion(self):
        self.assertIn("fn evaluate_promotion", self.content)

    def test_has_all_error_codes(self):
        for code in ["QPR_SCHEMA_FAILED", "QPR_NOT_AUTHENTICATED", "QPR_NOT_REACHABLE",
                     "QPR_NOT_PINNED", "QPR_INVALID_RULE"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestPromotionSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-3cm3_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-QPR-SCHEMA-GATED", "INV-QPR-AUTHENTICATED",
                    "INV-QPR-RECEIPT", "INV-QPR-FAIL-CLOSED"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["QPR_SCHEMA_FAILED", "QPR_NOT_AUTHENTICATED", "QPR_NOT_REACHABLE",
                     "QPR_NOT_PINNED", "QPR_INVALID_RULE"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestPromotionIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = ROOT / "tests/integration/quarantine_promotion_gate.rs"
        self.assertTrue(self.integ_path.is_file())
        self.content = self.integ_path.read_text(encoding="utf-8")

    def test_covers_schema_gated(self):
        self.assertIn("inv_qpr_schema_gated", self.content)

    def test_covers_authenticated(self):
        self.assertIn("inv_qpr_authenticated", self.content)

    def test_covers_receipt(self):
        self.assertIn("inv_qpr_receipt", self.content)

    def test_covers_fail_closed(self):
        self.assertIn("inv_qpr_fail_closed", self.content)


class TestPromotionCheckerCli(unittest.TestCase):

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

        self.assertEqual(evidence["gate"], "quarantine_promotion_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["QPR-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-3cm3:", result.stdout)

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
