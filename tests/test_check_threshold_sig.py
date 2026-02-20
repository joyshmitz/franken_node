"""Unit tests for check_threshold_sig.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestThresholdSigFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/threshold_sig/verification_scenarios.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixture_has_cases(self):
        path = os.path.join(ROOT, "fixtures/threshold_sig/verification_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_pass_and_fail(self):
        path = os.path.join(ROOT, "fixtures/threshold_sig/verification_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        verified = [c for c in data["cases"] if c.get("expected_verified") is True]
        rejected = [c for c in data["cases"] if c.get("expected_verified") is False]
        self.assertGreater(len(verified), 0)
        self.assertGreater(len(rejected), 0)


class TestThresholdSigVectors(unittest.TestCase):

    def test_vectors_exist(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-35q1/threshold_signature_vectors.json")
        self.assertTrue(os.path.isfile(path))

    def test_vectors_valid(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-35q1/threshold_signature_vectors.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("vectors", data)
        self.assertGreaterEqual(len(data["vectors"]), 2)

    def test_vectors_have_both_results(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-35q1/threshold_signature_vectors.json")
        with open(path) as f:
            data = json.load(f)
        results = [v["result"] for v in data["vectors"]]
        self.assertIn("verified", results)
        self.assertIn("rejected", results)


class TestThresholdSigImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/security/threshold_sig.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_threshold_config(self):
        self.assertIn("struct ThresholdConfig", self.content)

    def test_has_signer_key(self):
        self.assertIn("struct SignerKey", self.content)

    def test_has_partial_signature(self):
        self.assertIn("struct PartialSignature", self.content)

    def test_has_publication_artifact(self):
        self.assertIn("struct PublicationArtifact", self.content)

    def test_has_verification_result(self):
        self.assertIn("struct VerificationResult", self.content)

    def test_has_failure_reason(self):
        self.assertIn("enum FailureReason", self.content)

    def test_has_verify_threshold(self):
        self.assertIn("fn verify_threshold", self.content)

    def test_has_all_failure_reasons(self):
        for reason in ["BelowThreshold", "UnknownSigner", "InvalidSignature", "DuplicateSigner"]:
            self.assertIn(reason, self.content, f"Missing reason {reason}")

    def test_has_all_error_codes(self):
        for code in ["THRESH_BELOW_QUORUM", "THRESH_UNKNOWN_SIGNER",
                     "THRESH_INVALID_SIG", "THRESH_CONFIG_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestThresholdSigSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-35q1_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-THRESH-QUORUM", "INV-THRESH-PARTIAL-REJECT",
                    "INV-THRESH-STABLE-REASON", "INV-THRESH-NO-DUPLICATE"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["THRESH_BELOW_QUORUM", "THRESH_UNKNOWN_SIGNER",
                     "THRESH_INVALID_SIG", "THRESH_CONFIG_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_failure_reason_type(self):
        self.assertIn("FailureReason", self.content)


if __name__ == "__main__":
    unittest.main()
