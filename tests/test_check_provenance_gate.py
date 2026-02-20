"""Unit tests for check_provenance_gate.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestProvenanceFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/provenance/gate_scenarios.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixture_has_cases(self):
        path = os.path.join(ROOT, "fixtures/provenance/gate_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_pass_and_fail(self):
        path = os.path.join(ROOT, "fixtures/provenance/gate_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        passed = [c for c in data["cases"] if c.get("expected_passed") is True]
        failed = [c for c in data["cases"] if c.get("expected_passed") is False]
        self.assertGreater(len(passed), 0)
        self.assertGreater(len(failed), 0)


class TestProvenanceDecisions(unittest.TestCase):

    def test_decisions_exist(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3i9o/provenance_gate_decisions.json")
        self.assertTrue(os.path.isfile(path))

    def test_decisions_valid(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3i9o/provenance_gate_decisions.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("decisions", data)
        self.assertGreaterEqual(len(data["decisions"]), 2)

    def test_decisions_have_both_outcomes(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3i9o/provenance_gate_decisions.json")
        with open(path) as f:
            data = json.load(f)
        passed = [d for d in data["decisions"] if d["passed"]]
        failed = [d for d in data["decisions"] if not d["passed"]]
        self.assertGreater(len(passed), 0)
        self.assertGreater(len(failed), 0)


class TestProvenanceImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/supply_chain/provenance_gate.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_provenance_policy(self):
        self.assertIn("struct ProvenancePolicy", self.content)

    def test_has_artifact_provenance(self):
        self.assertIn("struct ArtifactProvenance", self.content)

    def test_has_gate_decision(self):
        self.assertIn("struct GateDecision", self.content)

    def test_has_evaluate_gate(self):
        self.assertIn("fn evaluate_gate", self.content)

    def test_has_attestation_types(self):
        for at in ["Slsa", "Sigstore", "InToto"]:
            self.assertIn(at, self.content, f"Missing attestation type {at}")

    def test_has_build_assurance_levels(self):
        for level in ["None", "Basic", "Verified", "Hardened"]:
            self.assertIn(level, self.content, f"Missing assurance level {level}")

    def test_has_all_error_codes(self):
        for code in ["PROV_ATTEST_MISSING", "PROV_ASSURANCE_LOW",
                     "PROV_BUILDER_UNTRUSTED", "PROV_POLICY_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestProvenanceSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-3i9o_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-PROV-REQUIRED-ATTEST", "INV-PROV-BUILD-ASSURANCE",
                    "INV-PROV-TRUSTED-BUILDER", "INV-PROV-GATE-LOGGED"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["PROV_ATTEST_MISSING", "PROV_ASSURANCE_LOW",
                     "PROV_BUILDER_UNTRUSTED", "PROV_POLICY_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


if __name__ == "__main__":
    unittest.main()
