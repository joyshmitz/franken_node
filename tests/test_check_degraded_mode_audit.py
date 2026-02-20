"""Unit tests for check_degraded_mode_audit.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestDegradedModeFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/security/degraded_mode_scenarios.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixture_has_cases(self):
        path = os.path.join(ROOT, "fixtures/security/degraded_mode_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_valid_and_invalid(self):
        path = os.path.join(ROOT, "fixtures/security/degraded_mode_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        valid = [c for c in data["cases"] if c.get("expected_valid") is True]
        invalid = [c for c in data["cases"] if c.get("expected_valid") is False]
        self.assertGreater(len(valid), 0)
        self.assertGreater(len(invalid), 0)


class TestDegradedModeEvents(unittest.TestCase):

    def test_events_exist(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-w0jq/degraded_mode_events.jsonl")
        self.assertTrue(os.path.isfile(path))

    def test_events_valid_jsonl(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-w0jq/degraded_mode_events.jsonl")
        with open(path) as f:
            lines = f.read().strip().split("\n")
        for line in lines:
            entry = json.loads(line)
            self.assertEqual(entry["event_type"], "degraded_mode_override")

    def test_events_have_required_fields(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-w0jq/degraded_mode_events.jsonl")
        with open(path) as f:
            lines = f.read().strip().split("\n")
        required = ["event_type", "action_id", "actor", "tier",
                    "revocation_age_secs", "max_age_secs", "override_reason",
                    "trace_id", "timestamp"]
        for line in lines:
            entry = json.loads(line)
            for field in required:
                self.assertIn(field, entry, f"Missing field {field}")


class TestDegradedModeImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/security/degraded_mode_audit.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_event(self):
        self.assertIn("struct DegradedModeEvent", self.content)

    def test_has_log(self):
        self.assertIn("struct DegradedModeAuditLog", self.content)

    def test_has_error(self):
        self.assertIn("enum AuditError", self.content)

    def test_has_validate(self):
        self.assertIn("fn validate_schema", self.content)

    def test_has_emit(self):
        self.assertIn("fn emit", self.content)

    def test_has_find_by_action(self):
        self.assertIn("fn find_by_action", self.content)

    def test_has_find_by_trace(self):
        self.assertIn("fn find_by_trace", self.content)

    def test_has_all_error_codes(self):
        for code in ["DM_MISSING_FIELD", "DM_EVENT_NOT_FOUND", "DM_SCHEMA_VIOLATION"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestDegradedModeSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-w0jq_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-DM-EVENT-REQUIRED", "INV-DM-SCHEMA-COMPLETE",
                    "INV-DM-CORRELATION", "INV-DM-IMMUTABLE"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["DM_MISSING_FIELD", "DM_EVENT_NOT_FOUND", "DM_SCHEMA_VIOLATION"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestDegradedModeConformanceTests(unittest.TestCase):

    def setUp(self):
        self.conf_path = os.path.join(ROOT, "tests/conformance/degraded_mode_audit_events.rs")
        self.assertTrue(os.path.isfile(self.conf_path))
        with open(self.conf_path) as f:
            self.content = f.read()

    def test_covers_event_required(self):
        self.assertIn("inv_dm_event_required", self.content)

    def test_covers_schema(self):
        self.assertIn("inv_dm_schema", self.content)

    def test_covers_correlation(self):
        self.assertIn("inv_dm_correlation", self.content)

    def test_covers_immutable(self):
        self.assertIn("inv_dm_immutable", self.content)


if __name__ == "__main__":
    unittest.main()
