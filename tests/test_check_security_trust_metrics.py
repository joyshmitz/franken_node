"""Unit tests for scripts/check_security_trust_metrics.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_security_trust_metrics as mod


class TestConstants(unittest.TestCase):
    def test_required_type_count(self):
        self.assertEqual(len(mod.REQUIRED_TYPES), 9)

    def test_security_category_count(self):
        self.assertEqual(len(mod.SECURITY_CATEGORIES), 5)

    def test_trust_category_count(self):
        self.assertEqual(len(mod.TRUST_CATEGORIES), 5)

    def test_event_code_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_EVENT_CODES), 12)

    def test_invariant_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_INVARIANTS), 6)


class TestRunAllChecks(unittest.TestCase):
    def test_returns_list(self):
        checks = mod.run_all_checks()
        self.assertIsInstance(checks, list)

    def test_has_many_checks(self):
        checks = mod.run_all_checks()
        self.assertGreaterEqual(len(checks), 50)

    def test_required_keys(self):
        checks = mod.run_all_checks()
        for entry in checks:
            self.assertIn("check", entry)
            self.assertIn("pass", entry)
            self.assertIn("detail", entry)

    def test_all_checks_pass(self):
        checks = mod.run_all_checks()
        failing = [c for c in checks if not c["pass"]]
        self.assertEqual(
            len(failing), 0,
            "\n".join(f"FAIL: {c['check']} :: {c['detail']}" for c in failing),
        )


class TestRunAll(unittest.TestCase):
    def test_structure(self):
        result = mod.run_all()
        for key in [
            "bead_id", "title", "section", "gate", "verdict",
            "overall_pass", "total", "passed", "failed",
            "security_categories", "trust_categories", "checks",
        ]:
            self.assertIn(key, result)

    def test_identity(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-wzjl")
        self.assertEqual(result["section"], "14")

    def test_pass_verdict(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failure_summary(result))
        self.assertTrue(result["overall_pass"])

    def test_json_serializable(self):
        result = mod.run_all()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-wzjl")

    def _failure_summary(self, result):
        failures = [c for c in result.get("checks", []) if not c.get("pass")]
        return "\n".join(f"FAIL: {c['check']} :: {c['detail']}" for c in failures)


class TestSelfTest(unittest.TestCase):
    def test_self_test(self):
        self.assertTrue(mod.self_test())


class TestKeyChecks(unittest.TestCase):
    def test_rust_module(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertTrue(checks["rust_module_exists"]["pass"])

    def test_tools_mod(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertTrue(checks["tools_mod_registration"]["pass"])

    def test_gate_behavior(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertTrue(checks["gate_behavior"]["pass"])

    def test_confidence_intervals(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertTrue(checks["confidence_intervals"]["pass"])

    def test_formula_versioning(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertTrue(checks["formula_versioning"]["pass"])

    def test_content_hash(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertTrue(checks["content_hash"]["pass"])

    def test_inline_tests(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertTrue(checks["inline_tests"]["pass"])

    def test_spec_contract(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertTrue(checks["spec_contract"]["pass"])

    def test_all_security_categories(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        for cat in mod.SECURITY_CATEGORIES:
            key = f"security_category_{cat}"
            self.assertIn(key, checks)
            self.assertTrue(checks[key]["pass"], f"{key}: {checks[key]['detail']}")

    def test_all_trust_categories(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        for cat in mod.TRUST_CATEGORIES:
            key = f"trust_category_{cat}"
            self.assertIn(key, checks)
            self.assertTrue(checks[key]["pass"], f"{key}: {checks[key]['detail']}")

    def test_all_invariants(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        for inv in mod.REQUIRED_INVARIANTS:
            key = f"invariant_{inv}"
            self.assertIn(key, checks)
            self.assertTrue(checks[key]["pass"], f"{key}: {checks[key]['detail']}")


if __name__ == "__main__":
    unittest.main()
