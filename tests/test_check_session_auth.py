"""Unit tests for scripts/check_session_auth.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_session_auth as mod


class TestConstants(unittest.TestCase):
    def test_required_structs_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_STRUCTS), 8)

    def test_required_event_codes_count(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 4)

    def test_required_error_codes_count(self):
        self.assertEqual(len(mod.REQUIRED_ERROR_CODES), 6)

    def test_required_invariants_count(self):
        self.assertEqual(len(mod.REQUIRED_INVARIANTS), 4)

    def test_required_functions_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_FUNCTIONS), 14)

    def test_required_spec_sections_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_SPEC_SECTIONS), 11)

    def test_session_states_count(self):
        self.assertEqual(len(mod.SESSION_STATES), 4)

    def test_key_roles_count(self):
        self.assertEqual(len(mod.KEY_ROLES), 2)

    def test_directions_count(self):
        self.assertEqual(len(mod.DIRECTIONS), 2)

    def test_required_policy_content_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_POLICY_CONTENT), 13)


class TestSimulation(unittest.TestCase):
    def test_strict_monotonicity(self):
        result = mod.simulate_session_lifecycle()
        self.assertTrue(result["strict_monotonicity"])

    def test_windowed_ooo(self):
        result = mod.simulate_session_lifecycle()
        self.assertTrue(result["windowed_ooo_accepted"])

    def test_replay_detected(self):
        result = mod.simulate_session_lifecycle()
        self.assertTrue(result["replay_detected"])

    def test_terminated_rejects(self):
        result = mod.simulate_session_lifecycle()
        self.assertTrue(result["terminated_rejects"])

    def test_independent_counters(self):
        result = mod.simulate_session_lifecycle()
        self.assertTrue(result["independent_counters"])

    def test_max_sessions_enforced(self):
        result = mod.simulate_session_lifecycle()
        self.assertTrue(result["max_sessions_enforced"])

    def test_role_key_validation(self):
        result = mod.simulate_session_lifecycle()
        self.assertTrue(result["role_key_validation"])

    def test_event_codes_count(self):
        result = mod.simulate_session_lifecycle()
        self.assertEqual(result["event_codes_count"], 4)

    def test_error_codes_count(self):
        result = mod.simulate_session_lifecycle()
        self.assertEqual(result["error_codes_count"], 6)


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-oty")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.10")

    def test_zero_failing(self):
        result = mod.run_checks()
        self.assertEqual(result["failed"], 0, self._failing(result))

    def test_many_checks(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["total"], 100)

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["pass"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestRunAll(unittest.TestCase):
    def test_run_all_alias(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-oty")
        self.assertIn("verdict", result)


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok, f"self_test failed with {sum(1 for c in checks if not c['pass'])} failures")


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        result = mod.run_checks()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-oty")

    def test_all_fields(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "verdict", "total", "passed", "failed", "checks"]:
            self.assertIn(key, result)


class TestHelpers(unittest.TestCase):
    def test_sha256_deterministic(self):
        h1 = mod._sha256_hex(b"test data")
        h2 = mod._sha256_hex(b"test data")
        self.assertEqual(h1, h2)

    def test_sha256_distinct(self):
        h1 = mod._sha256_hex(b"data-a")
        h2 = mod._sha256_hex(b"data-b")
        self.assertNotEqual(h1, h2)


class TestFileChecks(unittest.TestCase):
    def test_impl_exists(self):
        result = mod.run_checks()
        impl_check = next(
            c for c in result["checks"] if "session_auth implementation" in c["check"]
        )
        self.assertTrue(impl_check["pass"])

    def test_spec_exists(self):
        result = mod.run_checks()
        spec_check = next(c for c in result["checks"] if "contract spec" in c["check"])
        self.assertTrue(spec_check["pass"])

    def test_policy_exists(self):
        result = mod.run_checks()
        policy_check = next(c for c in result["checks"] if "policy document" in c["check"])
        self.assertTrue(policy_check["pass"])


class TestPolicyContent(unittest.TestCase):
    def test_policy_invariants_checked(self):
        result = mod.run_checks()
        policy_checks = [c for c in result["checks"] if c["check"].startswith("policy:")]
        self.assertGreaterEqual(len(policy_checks), 13)
        for c in policy_checks:
            self.assertTrue(c["pass"], f"Policy check failed: {c['check']}")

    def test_policy_file_path(self):
        self.assertTrue(mod.POLICY_FILE.name.endswith(".md"))
        self.assertIn("session_authenticated_control", mod.POLICY_FILE.name)


if __name__ == "__main__":
    unittest.main()
