"""Unit tests for check_network_guard.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestNetworkGuardFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/network_guard/egress_policy_scenarios.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixture_has_cases(self):
        path = os.path.join(ROOT, "fixtures/network_guard/egress_policy_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_allow_and_deny(self):
        path = os.path.join(ROOT, "fixtures/network_guard/egress_policy_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        actions = [c["expected_action"] for c in data["cases"]]
        self.assertIn("allow", actions)
        self.assertIn("deny", actions)

    def test_fixture_cases_have_fields(self):
        path = os.path.join(ROOT, "fixtures/network_guard/egress_policy_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        for case in data["cases"]:
            self.assertIn("host", case)
            self.assertIn("port", case)
            self.assertIn("protocol", case)
            self.assertIn("expected_action", case)


class TestAuditSamples(unittest.TestCase):

    def test_audit_jsonl_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2m2b/network_guard_audit_samples.jsonl")
        self.assertTrue(os.path.isfile(path))

    def test_audit_jsonl_valid(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2m2b/network_guard_audit_samples.jsonl")
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertGreaterEqual(len(lines), 2)
        for line in lines:
            event = json.loads(line)
            self.assertIn("trace_id", event)
            self.assertIn("action", event)
            self.assertIn("connector_id", event)

    def test_audit_has_allow_and_deny(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2m2b/network_guard_audit_samples.jsonl")
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip()]
        actions = [json.loads(l)["action"] for l in lines]
        self.assertIn("allow", actions)
        self.assertIn("deny", actions)


class TestNetworkGuardImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/security/network_guard.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_network_guard(self):
        self.assertIn("struct NetworkGuard", self.content)

    def test_has_egress_policy(self):
        self.assertIn("struct EgressPolicy", self.content)

    def test_has_audit_event(self):
        self.assertIn("struct AuditEvent", self.content)

    def test_has_process_egress(self):
        self.assertIn("fn process_egress", self.content)

    def test_has_host_matching(self):
        self.assertIn("fn host_matches", self.content)

    def test_has_both_protocols(self):
        self.assertIn("Http", self.content)
        self.assertIn("Tcp", self.content)

    def test_has_all_error_codes(self):
        for code in ["GUARD_POLICY_INVALID", "GUARD_EGRESS_DENIED", "GUARD_AUDIT_FAILED"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestNetworkGuardSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-2m2b_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-GUARD-ALL-EGRESS", "INV-GUARD-DEFAULT-DENY",
                    "INV-GUARD-AUDIT", "INV-GUARD-ORDERED"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["GUARD_POLICY_INVALID", "GUARD_EGRESS_DENIED", "GUARD_AUDIT_FAILED"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_audit_event_schema(self):
        self.assertIn("Audit Event", self.content)
        self.assertIn("trace_id", self.content)


if __name__ == "__main__":
    unittest.main()
