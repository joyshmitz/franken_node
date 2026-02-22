"""Unit tests for scripts/check_vef_perf_budget.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_vef_perf_budget as mod


class TestConstants(unittest.TestCase):
    def test_hot_path_count(self):
        self.assertEqual(len(mod.VEF_HOT_PATHS), 5)

    def test_mode_count(self):
        self.assertEqual(len(mod.VEF_MODES), 3)

    def test_event_code_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_EVENT_CODES), 8)

    def test_invariant_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_INVARIANTS), 6)

    def test_normal_budgets_cover_all_paths(self):
        for path in mod.VEF_HOT_PATHS:
            self.assertIn(path, mod.NORMAL_BUDGETS)

    def test_mode_multipliers(self):
        self.assertAlmostEqual(mod.MODE_MULTIPLIERS["normal"], 1.0)
        self.assertAlmostEqual(mod.MODE_MULTIPLIERS["restricted"], 1.5)
        self.assertAlmostEqual(mod.MODE_MULTIPLIERS["quarantine"], 2.0)


class TestRunAllChecks(unittest.TestCase):
    def test_returns_list(self):
        checks = mod.run_all_checks()
        self.assertIsInstance(checks, list)

    def test_has_many_checks(self):
        checks = mod.run_all_checks()
        self.assertGreaterEqual(len(checks), 30)

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
            "hot_paths", "modes", "checks",
        ]:
            self.assertIn(key, result)

    def test_identity(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-ufk5")
        self.assertEqual(result["section"], "10.18")
        self.assertFalse(result["gate"])

    def test_pass_verdict(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failure_summary(result))
        self.assertTrue(result["overall_pass"])
        self.assertEqual(result["failed"], 0, self._failure_summary(result))

    def test_json_serializable(self):
        result = mod.run_all()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-ufk5")

    def _failure_summary(self, result):
        failures = [c for c in result.get("checks", []) if not c.get("pass")]
        return "\n".join(f"FAIL: {c['check']} :: {c['detail']}" for c in failures)


class TestSelfTest(unittest.TestCase):
    def test_self_test(self):
        self.assertTrue(mod.self_test())


class TestKeyChecks(unittest.TestCase):
    def test_rust_module_check(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertIn("rust_module_exists", checks)
        self.assertTrue(checks["rust_module_exists"]["pass"])

    def test_mod_registration_check(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertIn("mod_registration", checks)
        self.assertTrue(checks["mod_registration"]["pass"])

    def test_hot_path_checks_pass(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        for path in mod.VEF_HOT_PATHS:
            key = f"hot_path_{path}"
            self.assertIn(key, checks, f"check {key} missing")
            self.assertTrue(checks[key]["pass"], f"{key}: {checks[key]['detail']}")

    def test_mode_checks_pass(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        for mode in mod.VEF_MODES:
            key = f"mode_{mode}"
            self.assertIn(key, checks, f"check {key} missing")
            self.assertTrue(checks[key]["pass"], f"{key}: {checks[key]['detail']}")

    def test_event_code_checks_pass(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        for code in mod.REQUIRED_EVENT_CODES:
            key = f"event_code_{code}"
            self.assertIn(key, checks, f"check {key} missing")
            self.assertTrue(checks[key]["pass"], f"{key}: {checks[key]['detail']}")

    def test_spec_contract_check(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertIn("spec_contract", checks)
        self.assertTrue(checks["spec_contract"]["pass"])

    def test_gate_struct_check(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertIn("gate_struct", checks)
        self.assertTrue(checks["gate_struct"]["pass"])


if __name__ == "__main__":
    unittest.main()
