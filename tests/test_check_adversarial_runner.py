"""Unit tests for scripts/check_adversarial_runner.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_adversarial_runner as mod


class TestConstants(unittest.TestCase):
    def test_campaign_category_count(self):
        self.assertEqual(len(mod.CAMPAIGN_CATEGORIES), 5)

    def test_mutation_strategy_count(self):
        self.assertEqual(len(mod.MUTATION_STRATEGIES), 4)

    def test_event_code_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_EVENT_CODES), 8)

    def test_invariant_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_INVARIANTS), 7)


class TestRunAllChecks(unittest.TestCase):
    def test_returns_list(self):
        checks = mod.run_all_checks()
        self.assertIsInstance(checks, list)

    def test_has_many_checks(self):
        checks = mod.run_all_checks()
        self.assertGreaterEqual(len(checks), 40)

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
            "campaign_categories", "mutation_strategies", "checks",
        ]:
            self.assertIn(key, result)

    def test_identity(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-9is")
        self.assertEqual(result["section"], "10.9")

    def test_pass_verdict(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failure_summary(result))
        self.assertTrue(result["overall_pass"])

    def test_json_serializable(self):
        result = mod.run_all()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-9is")

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

    def test_mod_registration(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertTrue(checks["mod_registration"]["pass"])

    def test_categories_pass(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        for cat_id, _ in mod.CAMPAIGN_CATEGORIES:
            key = f"category_{cat_id}"
            self.assertIn(key, checks)
            self.assertTrue(checks[key]["pass"], f"{key}: {checks[key]['detail']}")

    def test_mutations_pass(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        for mut_id, _ in mod.MUTATION_STRATEGIES:
            key = f"mutation_{mut_id}"
            self.assertIn(key, checks)
            self.assertTrue(checks[key]["pass"], f"{key}: {checks[key]['detail']}")

    def test_corpus_fixture(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertTrue(checks["corpus_fixture_exists"]["pass"])
        self.assertTrue(checks["corpus_fixture_valid_json"]["pass"])
        self.assertTrue(checks["corpus_fixture_categories"]["pass"])

    def test_spec_contract(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        self.assertTrue(checks["spec_contract"]["pass"])


if __name__ == "__main__":
    unittest.main()
