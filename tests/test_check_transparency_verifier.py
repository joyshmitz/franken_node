"""Unit tests for check_transparency_verifier.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestTransparencyFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/transparency_log/inclusion_proof_scenarios.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixture_has_cases(self):
        path = os.path.join(ROOT, "fixtures/transparency_log/inclusion_proof_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_pass_and_fail(self):
        path = os.path.join(ROOT, "fixtures/transparency_log/inclusion_proof_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        verified = [c for c in data["cases"] if c.get("expected_verified") is True]
        rejected = [c for c in data["cases"] if c.get("expected_verified") is False]
        self.assertGreater(len(verified), 0)
        self.assertGreater(len(rejected), 0)


class TestTransparencyReceipts(unittest.TestCase):

    def test_receipts_exist(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1z9s/transparency_proof_receipts.json")
        self.assertTrue(os.path.isfile(path))

    def test_receipts_valid(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1z9s/transparency_proof_receipts.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("receipts", data)
        self.assertGreaterEqual(len(data["receipts"]), 2)

    def test_receipts_have_both_outcomes(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1z9s/transparency_proof_receipts.json")
        with open(path) as f:
            data = json.load(f)
        verified = [r for r in data["receipts"] if r["verified"]]
        rejected = [r for r in data["receipts"] if not r["verified"]]
        self.assertGreater(len(verified), 0)
        self.assertGreater(len(rejected), 0)

    def test_receipts_have_trace_ids(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1z9s/transparency_proof_receipts.json")
        with open(path) as f:
            data = json.load(f)
        for r in data["receipts"]:
            self.assertIn("trace_id", r)


class TestTransparencyImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/supply_chain/transparency_verifier.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_log_root(self):
        self.assertIn("struct LogRoot", self.content)

    def test_has_inclusion_proof(self):
        self.assertIn("struct InclusionProof", self.content)

    def test_has_transparency_policy(self):
        self.assertIn("struct TransparencyPolicy", self.content)

    def test_has_proof_receipt(self):
        self.assertIn("struct ProofReceipt", self.content)

    def test_has_verify_inclusion(self):
        self.assertIn("fn verify_inclusion", self.content)

    def test_has_recompute_root(self):
        self.assertIn("fn recompute_root", self.content)

    def test_has_all_failure_types(self):
        for ft in ["ProofMissing", "RootNotPinned", "PathInvalid", "LeafMismatch"]:
            self.assertIn(ft, self.content, f"Missing failure type {ft}")

    def test_has_all_error_codes(self):
        for code in ["TLOG_PROOF_MISSING", "TLOG_ROOT_NOT_PINNED",
                     "TLOG_PATH_INVALID", "TLOG_LEAF_MISMATCH"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestTransparencySpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-1z9s_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-TLOG-REQUIRED", "INV-TLOG-VERIFY",
                    "INV-TLOG-PINNED-ROOT", "INV-TLOG-REPLAYABLE"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["TLOG_PROOF_MISSING", "TLOG_ROOT_NOT_PINNED",
                     "TLOG_PATH_INVALID", "TLOG_LEAF_MISMATCH"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_proof_failure_type(self):
        self.assertIn("ProofFailure", self.content)


if __name__ == "__main__":
    unittest.main()
