"""Unit tests for check_retention_policy.py verification logic."""

import json
import os
import unittest
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestRetentionMatrix(unittest.TestCase):

    def test_matrix_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1p2b/retention_policy_matrix.json")
        self.assertTrue(os.path.isfile(path))

    def test_matrix_valid_json(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1p2b/retention_policy_matrix.json")
        data = json.JSONDecoder().decode(Path(path).read_text(encoding="utf-8"))
        self.assertIn("matrix", data)
        self.assertGreaterEqual(len(data["matrix"]), 5)

    def test_has_both_classes(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1p2b/retention_policy_matrix.json")
        data = json.JSONDecoder().decode(Path(path).read_text(encoding="utf-8"))
        classes = {e["retention_class"] for e in data["matrix"]}
        self.assertIn("required", classes)
        self.assertIn("ephemeral", classes)


class TestRetentionPolicyImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/retention_policy.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        self.content = Path(self.impl_path).read_text(encoding="utf-8")

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
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-1p2b_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        self.content = Path(self.spec_path).read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-CPR-CLASSIFIED", "INV-CPR-REQUIRED-DURABLE",
                    "INV-CPR-EPHEMERAL-POLICY", "INV-CPR-AUDITABLE"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")


class TestRetentionIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/retention_class_enforcement.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        self.content = Path(self.integ_path).read_text(encoding="utf-8")

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
        self.check_path = os.path.join(ROOT, "scripts/check_retention_policy.py")
        self.assertTrue(os.path.isfile(self.check_path))
        self.content = Path(self.check_path).read_text(encoding="utf-8")

    def test_checker_clears_accumulated_checks(self):
        self.assertIn("CHECKS.clear()", self.content)

    def test_checker_uses_rch_exec_not_local_cargo(self):
        self.assertIn('"rch", "exec", "--", "cargo"', self.content)
        self.assertIn("check=False", self.content)


if __name__ == "__main__":
    unittest.main()
