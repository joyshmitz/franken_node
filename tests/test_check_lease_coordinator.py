"""Unit tests for check_lease_coordinator.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestLeaseCoordinatorVectors(unittest.TestCase):

    def test_vectors_exist(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2vs4/lease_quorum_vectors.json")
        self.assertTrue(os.path.isfile(path))

    def test_vectors_valid(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2vs4/lease_quorum_vectors.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("vectors", data)
        self.assertGreaterEqual(len(data["vectors"]), 4)

    def test_vectors_have_pass_and_fail(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2vs4/lease_quorum_vectors.json")
        with open(path) as f:
            data = json.load(f)
        passed = [v for v in data["vectors"] if v.get("expected_passed") is True]
        failed = [v for v in data["vectors"] if v.get("expected_passed") is False]
        self.assertGreater(len(passed), 0)
        self.assertGreater(len(failed), 0)


class TestLeaseCoordinatorImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/lease_coordinator.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_coordinator_candidate(self):
        self.assertIn("struct CoordinatorCandidate", self.content)

    def test_has_coordinator_selection(self):
        self.assertIn("struct CoordinatorSelection", self.content)

    def test_has_quorum_config(self):
        self.assertIn("struct QuorumConfig", self.content)

    def test_has_select_coordinator(self):
        self.assertIn("fn select_coordinator", self.content)

    def test_has_verify_quorum(self):
        self.assertIn("fn verify_quorum", self.content)

    def test_has_verification_failure(self):
        self.assertIn("enum VerificationFailure", self.content)

    def test_has_all_error_codes(self):
        for code in ["LC_BELOW_QUORUM", "LC_INVALID_SIGNATURE",
                     "LC_UNKNOWN_SIGNER", "LC_NO_CANDIDATES"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestLeaseCoordinatorSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-2vs4_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-LC-DETERMINISTIC", "INV-LC-QUORUM-TIER",
                    "INV-LC-VERIFY-CLASSIFIED", "INV-LC-REPLAY"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["LC_BELOW_QUORUM", "LC_INVALID_SIGNATURE",
                     "LC_UNKNOWN_SIGNER", "LC_NO_CANDIDATES"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestLeaseCoordinatorConformance(unittest.TestCase):

    def setUp(self):
        self.conf_path = os.path.join(ROOT, "tests/conformance/lease_coordinator_selection.rs")
        self.assertTrue(os.path.isfile(self.conf_path))
        with open(self.conf_path) as f:
            self.content = f.read()

    def test_covers_deterministic(self):
        self.assertIn("inv_lc_deterministic", self.content)

    def test_covers_quorum_tier(self):
        self.assertIn("inv_lc_quorum_tier", self.content)

    def test_covers_classified(self):
        self.assertIn("inv_lc_verify_classified", self.content)

    def test_covers_replay(self):
        self.assertIn("inv_lc_replay", self.content)


if __name__ == "__main__":
    unittest.main()
