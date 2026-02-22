"""Unit tests for scripts/check_key_role_separation.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_key_role_separation as mod


class TestConstants(unittest.TestCase):
    def test_required_types_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TYPES), 4)

    def test_required_methods_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_METHODS), 8)

    def test_error_codes_count(self):
        self.assertEqual(len(mod.REQUIRED_ERROR_CODES), 4)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 4)

    def test_invariants_count(self):
        self.assertEqual(len(mod.REQUIRED_INVARIANTS), 4)

    def test_required_roles_count(self):
        self.assertEqual(len(mod.REQUIRED_ROLES), 4)

    def test_required_tests_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TESTS), 30)


class TestCheckFile(unittest.TestCase):
    def test_existing(self):
        result = mod.check_file(mod.IMPL, "test")
        self.assertTrue(result["pass"])

    def test_missing(self):
        result = mod.check_file(Path("/nonexistent/file.rs"), "ghost")
        self.assertFalse(result["pass"])


class TestCheckContent(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, ["pub enum KeyRole"], "type")
        self.assertTrue(results[0]["pass"])

    def test_missing(self):
        results = mod.check_content(mod.IMPL, ["NONEXISTENT_PATTERN_XYZ"], "type")
        self.assertFalse(results[0]["pass"])

    def test_missing_file(self):
        results = mod.check_content(Path("/no"), ["anything"], "type")
        self.assertFalse(results[0]["pass"])


class TestCheckModuleRegistered(unittest.TestCase):
    def test_registered(self):
        result = mod.check_module_registered()
        self.assertTrue(result["pass"])


class TestCheckTestCount(unittest.TestCase):
    def test_meets_minimum(self):
        result = mod.check_test_count(mod.IMPL)
        self.assertTrue(result["pass"], result["detail"])


class TestCheckRoleTags(unittest.TestCase):
    def test_all_tags_found(self):
        results = mod.check_role_tags(mod.IMPL)
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")


class TestCheckBindingFields(unittest.TestCase):
    def test_all_fields_found(self):
        results = mod.check_binding_fields(mod.IMPL)
        for r in results:
            self.assertTrue(r["pass"], f"{r['check']}: {r['detail']}")


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS", self._failing_details(result))

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead"], "bd-364")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.10")

    def test_zero_failing(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing_checks"], 0,
                         self._failing_details(result))

    def test_has_many_checks(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["summary"]["total_checks"], 60)

    def _failing_details(self, result):
        failures = [c for c in result["checks"] if not c["pass"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        result = mod.self_test()
        self.assertEqual(result["verdict"], "PASS")


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        result = mod.run_checks()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead"], "bd-364")

    def test_all_fields(self):
        result = mod.run_checks()
        for key in ["bead", "title", "section", "verdict", "summary", "checks"]:
            self.assertIn(key, result)


class TestAllTypes(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TYPES, "type")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllMethods(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_METHODS, "method")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllErrorCodes(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_ERROR_CODES, "error_code")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllEventCodes(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_EVENT_CODES, "event_code")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllInvariants(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_INVARIANTS, "invariant")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestAllRequiredTests(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TESTS, "test")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestSpecContent(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.SPEC, mod.SPEC_CONTENT, "spec")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


class TestPolicyContent(unittest.TestCase):
    def test_found(self):
        results = mod.check_content(mod.POLICY, mod.POLICY_CONTENT, "policy")
        for r in results:
            self.assertTrue(r["pass"], r["check"])


if __name__ == "__main__":
    unittest.main()
