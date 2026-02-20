"""Unit tests for check_manifest_negotiation.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestManifestNegotiationFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/manifest_negotiation/negotiation_scenarios.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixture_has_cases(self):
        path = os.path.join(ROOT, "fixtures/manifest_negotiation/negotiation_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 5)

    def test_fixture_has_accepted_and_rejected(self):
        path = os.path.join(ROOT, "fixtures/manifest_negotiation/negotiation_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        outcomes = [c["expected_outcome"] for c in data["cases"]]
        self.assertIn("accepted", outcomes)
        self.assertIn("rejected", outcomes)

    def test_fixture_cases_have_manifest_fields(self):
        path = os.path.join(ROOT, "fixtures/manifest_negotiation/negotiation_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        for case in data["cases"]:
            self.assertIn("manifest", case)
            self.assertIn("host", case)
            self.assertIn("expected_outcome", case)
            m = case["manifest"]
            self.assertIn("version", m)
            self.assertIn("required_features", m)
            self.assertIn("transport_caps", m)


class TestManifestNegotiationTrace(unittest.TestCase):

    def test_trace_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-17mb/manifest_negotiation_trace.json")
        self.assertTrue(os.path.isfile(path))

    def test_trace_valid_json(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-17mb/manifest_negotiation_trace.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("negotiations", data)
        self.assertGreaterEqual(len(data["negotiations"]), 2)

    def test_trace_has_both_outcomes(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-17mb/manifest_negotiation_trace.json")
        with open(path) as f:
            data = json.load(f)
        outcomes = [n["outcome"] for n in data["negotiations"]]
        self.assertIn("accepted", outcomes)
        self.assertIn("rejected", outcomes)

    def test_trace_has_trace_ids(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-17mb/manifest_negotiation_trace.json")
        with open(path) as f:
            data = json.load(f)
        for n in data["negotiations"]:
            self.assertIn("trace_id", n)


class TestManifestNegotiationImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/manifest_negotiation.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_semver(self):
        self.assertIn("struct SemVer", self.content)

    def test_has_connector_manifest(self):
        self.assertIn("struct ConnectorManifest", self.content)

    def test_has_host_capabilities(self):
        self.assertIn("struct HostCapabilities", self.content)

    def test_has_negotiation_result(self):
        self.assertIn("struct NegotiationResult", self.content)

    def test_has_negotiate_fn(self):
        self.assertIn("fn negotiate", self.content)

    def test_has_check_version(self):
        self.assertIn("fn check_version", self.content)

    def test_has_check_features(self):
        self.assertIn("fn check_features", self.content)

    def test_has_check_transport(self):
        self.assertIn("fn check_transport", self.content)

    def test_has_semantic_ordering(self):
        self.assertIn("impl Ord for SemVer", self.content)

    def test_has_all_transport_caps(self):
        for cap in ["Http1", "Http2", "Http3", "WebSocket", "Grpc"]:
            self.assertIn(cap, self.content, f"Missing transport cap {cap}")

    def test_has_all_error_codes(self):
        for code in ["MANIFEST_VERSION_UNSUPPORTED", "MANIFEST_FEATURE_MISSING",
                     "MANIFEST_TRANSPORT_MISMATCH", "MANIFEST_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestManifestNegotiationSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-17mb_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-MANIFEST-SEMVER", "INV-MANIFEST-FAIL-CLOSED",
                    "INV-MANIFEST-FEATURES", "INV-MANIFEST-TRANSPORT"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["MANIFEST_VERSION_UNSUPPORTED", "MANIFEST_FEATURE_MISSING",
                     "MANIFEST_TRANSPORT_MISMATCH", "MANIFEST_INVALID"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_outcome_types(self):
        self.assertIn("Accepted", self.content)
        self.assertIn("Rejected", self.content)


if __name__ == "__main__":
    unittest.main()
