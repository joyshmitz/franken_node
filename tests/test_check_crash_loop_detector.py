"""Unit tests for check_crash_loop_detector.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestCrashLoopFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/runtime/crash_loop_scenarios.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixture_has_cases(self):
        path = os.path.join(ROOT, "fixtures/runtime/crash_loop_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_has_threshold_case(self):
        path = os.path.join(ROOT, "fixtures/runtime/crash_loop_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        threshold = [c for c in data["cases"] if "threshold" in c.get("id", "")]
        self.assertGreater(len(threshold), 0)

    def test_fixture_has_error_code_cases(self):
        path = os.path.join(ROOT, "fixtures/runtime/crash_loop_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        codes = {c.get("expected_error_code") for c in data["cases"] if c.get("expected_error_code")}
        self.assertIn("CLD_NO_KNOWN_GOOD", codes)
        self.assertIn("CLD_PIN_UNTRUSTED", codes)


class TestCrashLoopBundle(unittest.TestCase):

    def test_bundle_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2yc4/crash_loop_incident_bundle.json")
        self.assertTrue(os.path.isfile(path))

    def test_bundle_valid(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2yc4/crash_loop_incident_bundle.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("incidents", data)
        self.assertGreaterEqual(len(data["incidents"]), 2)

    def test_bundle_has_rollback_allowed(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2yc4/crash_loop_incident_bundle.json")
        with open(path) as f:
            data = json.load(f)
        allowed = [i for i in data["incidents"] if i["decision"]["rollback_allowed"]]
        self.assertGreater(len(allowed), 0)

    def test_bundle_has_rollback_denied(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-2yc4/crash_loop_incident_bundle.json")
        with open(path) as f:
            data = json.load(f)
        denied = [i for i in data["incidents"] if not i["decision"]["rollback_allowed"]]
        self.assertGreater(len(denied), 0)


class TestCrashLoopImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/runtime/crash_loop_detector.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_crash_loop_config(self):
        self.assertIn("struct CrashLoopConfig", self.content)

    def test_has_crash_event(self):
        self.assertIn("struct CrashEvent", self.content)

    def test_has_known_good_pin(self):
        self.assertIn("struct KnownGoodPin", self.content)

    def test_has_rollback_decision(self):
        self.assertIn("struct RollbackDecision", self.content)

    def test_has_crash_loop_detector(self):
        self.assertIn("struct CrashLoopDetector", self.content)

    def test_has_evaluate(self):
        self.assertIn("fn evaluate", self.content)

    def test_has_sliding_window(self):
        self.assertIn("crashes_in_window", self.content)

    def test_has_cooldown(self):
        self.assertIn("in_cooldown", self.content)

    def test_has_all_error_codes(self):
        for code in ["CLD_THRESHOLD_EXCEEDED", "CLD_NO_KNOWN_GOOD",
                     "CLD_PIN_UNTRUSTED", "CLD_COOLDOWN_ACTIVE"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_incident_type(self):
        self.assertIn("struct CrashLoopIncident", self.content)


class TestCrashLoopSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-2yc4_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-CLD-THRESHOLD", "INV-CLD-ROLLBACK-AUTO",
                    "INV-CLD-TRUST-POLICY", "INV-CLD-AUDIT"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["CLD_THRESHOLD_EXCEEDED", "CLD_NO_KNOWN_GOOD",
                     "CLD_PIN_UNTRUSTED", "CLD_COOLDOWN_ACTIVE"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestCrashLoopIntegrationTests(unittest.TestCase):

    def setUp(self):
        self.integ_path = os.path.join(ROOT, "tests/integration/crash_loop_rollback.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_threshold(self):
        self.assertIn("inv_cld_threshold", self.content)

    def test_covers_rollback(self):
        self.assertIn("inv_cld_rollback", self.content)

    def test_covers_trust(self):
        self.assertIn("inv_cld_trust", self.content)

    def test_covers_audit(self):
        self.assertIn("inv_cld_audit", self.content)


if __name__ == "__main__":
    unittest.main()
