"""Unit tests for check_retention_policy.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_retention_policy.py"
MATRIX_PATH = ROOT / "artifacts/section_10_13/bd-1p2b/retention_policy_matrix.json"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-1p2b/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestRetentionMatrix(unittest.TestCase):

    def test_matrix_exists(self):
        self.assertTrue(MATRIX_PATH.is_file())

    def test_matrix_valid_json(self):
        data = decode_json_object(MATRIX_PATH.read_text(encoding="utf-8"))
        self.assertIn("matrix", data)
        self.assertGreaterEqual(len(data["matrix"]), 5)

    def test_has_both_classes(self):
        data = decode_json_object(MATRIX_PATH.read_text(encoding="utf-8"))
        classes = {e["retention_class"] for e in data["matrix"]}
        self.assertIn("required", classes)
        self.assertIn("ephemeral", classes)


class TestRetentionPolicyImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/retention_policy.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_retention_class(self):
        self.assertIn("enum RetentionClass", self.content)

    def test_has_retention_policy(self):
        self.assertIn("struct RetentionPolicy", self.content)

    def test_has_retention_registry(self):
        self.assertIn("struct RetentionRegistry", self.content)

    def test_has_retention_store(self):
        self.assertIn("struct RetentionStore", self.content)

    def test_has_all_error_codes(self):
        for code in ["CPR_UNCLASSIFIED", "CPR_DROP_REQUIRED", "CPR_INVALID_POLICY",
                     "CPR_STORAGE_FULL", "CPR_NOT_FOUND"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestRetentionPolicySpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-1p2b_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-CPR-CLASSIFIED", "INV-CPR-REQUIRED-DURABLE",
                    "INV-CPR-EPHEMERAL-POLICY", "INV-CPR-AUDITABLE"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")


class TestRetentionIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = ROOT / "tests/integration/retention_class_enforcement.rs"
        self.assertTrue(self.integ_path.is_file())
        self.content = self.integ_path.read_text(encoding="utf-8")

    def test_covers_classified(self):
        self.assertIn("inv_cpr_classified", self.content)

    def test_covers_required_durable(self):
        self.assertIn("inv_cpr_required_durable", self.content)

    def test_covers_ephemeral_policy(self):
        self.assertIn("inv_cpr_ephemeral_policy", self.content)

    def test_covers_auditable(self):
        self.assertIn("inv_cpr_auditable", self.content)


class TestRetentionChecker(unittest.TestCase):

    def setUp(self):
        self.assertTrue(SCRIPT.is_file())
        self.content = SCRIPT.read_text(encoding="utf-8")

    def test_checker_uses_explicit_rch_full_proof(self):
        for token in ['"rch"', '"exec"', '"--"', '"cargo"', '"connector::retention_policy"']:
            self.assertIn(token, self.content)
        self.assertIn("check=False", self.content)

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

        self.assertEqual(evidence["gate"], "retention_policy_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["CPR-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-1p2b:", result.stdout)

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
