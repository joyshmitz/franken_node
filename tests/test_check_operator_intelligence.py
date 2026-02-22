"""Unit tests for scripts/check_operator_intelligence.py (bd-y0v)."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_operator_intelligence as checker


class TestSelfTest(unittest.TestCase):
    def test_self_test_runs(self):
        ok = checker.self_test()
        self.assertTrue(ok)


class TestRunAllStructure(unittest.TestCase):
    def test_structure(self):
        result = checker.run_all()
        for key in ("bead_id", "section", "checks", "verdict",
                     "passed", "failed", "total", "all_passed", "status"):
            self.assertIn(key, result)

    def test_bead_id(self):
        result = checker.run_all()
        self.assertEqual(result["bead_id"], "bd-y0v")

    def test_section(self):
        result = checker.run_all()
        self.assertEqual(result["section"], "10.12")

    def test_title(self):
        result = checker.run_all()
        self.assertEqual(result["title"], "Operator Intelligence Recommendation Engine")

    def test_all_checks_have_required_keys(self):
        result = checker.run_all()
        for check in result["checks"]:
            self.assertIn("name", check)
            self.assertIn("passed", check)
            self.assertIn("detail", check)

    def test_pass_values_are_bool(self):
        result = checker.run_all()
        for check in result["checks"]:
            self.assertIsInstance(check["passed"], bool)

    def test_verdict_consistency(self):
        result = checker.run_all()
        if result["failed"] == 0:
            self.assertEqual(result["verdict"], "PASS")
            self.assertTrue(result["all_passed"])


class TestSpecChecks(unittest.TestCase):
    def test_spec_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "spec_exists")
        self.assertTrue(check["passed"], check["detail"])

    def test_event_codes(self):
        result = checker.run_all()
        for code in checker.EVENT_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"spec_event:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")

    def test_invariants(self):
        result = checker.run_all()
        for inv in checker.INVARIANTS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"spec_invariant:{inv}")
            self.assertTrue(check["passed"], f"{inv}: {check['detail']}")

    def test_error_codes(self):
        result = checker.run_all()
        for code in checker.ERROR_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"spec_error:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")


class TestRustChecks(unittest.TestCase):
    def test_rust_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "rust_exists")
        self.assertTrue(check["passed"], check["detail"])

    def test_event_codes(self):
        result = checker.run_all()
        for code in checker.EVENT_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"rust_event:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")

    def test_error_codes(self):
        result = checker.run_all()
        for code in checker.ERROR_CODES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"rust_error:{code}")
            self.assertTrue(check["passed"], f"{code}: {check['detail']}")

    def test_invariants(self):
        result = checker.run_all()
        for inv in checker.INVARIANTS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"rust_invariant:{inv}")
            self.assertTrue(check["passed"], f"{inv}: {check['detail']}")

    def test_types(self):
        result = checker.run_all()
        for typ in checker.REQUIRED_TYPES:
            check = next(c for c in result["checks"]
                         if c["name"] == f"rust_type:{typ}")
            self.assertTrue(check["passed"], f"{typ}: {check['detail']}")

    def test_methods(self):
        result = checker.run_all()
        for method in checker.REQUIRED_METHODS:
            check = next(c for c in result["checks"]
                         if c["name"] == f"rust_method:{method}")
            self.assertTrue(check["passed"], f"{method}: {check['detail']}")

    def test_rust_test_count(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "rust_test_count")
        self.assertTrue(check["passed"], check["detail"])

    def test_mod_registered(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "mod_registered")
        self.assertTrue(check["passed"], check["detail"])


class TestPolicyChecks(unittest.TestCase):
    def test_policy_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "policy_exists")
        self.assertTrue(check["passed"], check["detail"])

    def test_policy_topics(self):
        result = checker.run_all()
        topic_checks = [c for c in result["checks"]
                        if c["name"].startswith("policy_topic:")]
        self.assertTrue(len(topic_checks) > 0)
        for check in topic_checks:
            self.assertTrue(check["passed"], f"{check['name']}: {check['detail']}")


class TestArtifactChecks(unittest.TestCase):
    def test_evidence_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "evidence_exists")
        self.assertTrue(check["passed"], check["detail"])

    def test_summary_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "summary_exists")
        self.assertTrue(check["passed"], check["detail"])

    def test_test_file_exists(self):
        result = checker.run_all()
        check = next(c for c in result["checks"]
                     if c["name"] == "test_file_exists")
        self.assertTrue(check["passed"], check["detail"])


class TestConstants(unittest.TestCase):
    def test_event_code_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 10)

    def test_error_code_count(self):
        self.assertEqual(len(checker.ERROR_CODES), 6)

    def test_invariant_count(self):
        self.assertEqual(len(checker.INVARIANTS), 4)

    def test_type_count(self):
        self.assertEqual(len(checker.REQUIRED_TYPES), 9)


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_all()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "check_operator_intelligence.py"), "--json"],
            capture_output=True, text=True,
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data["bead_id"], "bd-y0v")
        self.assertIn("checks", data)

    def test_cli_self_test(self):
        proc = subprocess.run(
            [sys.executable,
             str(ROOT / "scripts" / "check_operator_intelligence.py"), "--self-test"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("self_test passed", proc.stdout)


class TestRustTestCategories(unittest.TestCase):
    def test_config_tests(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "rust_config_tests")
        self.assertTrue(check["passed"], check["detail"])

    def test_context_tests(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "rust_context_tests")
        self.assertTrue(check["passed"], check["detail"])

    def test_scoring_tests(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "rust_scoring_tests")
        self.assertTrue(check["passed"], check["detail"])

    def test_recommendation_tests(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "rust_recommendation_tests")
        self.assertTrue(check["passed"], check["detail"])

    def test_determinism_tests(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "rust_determinism_tests")
        self.assertTrue(check["passed"], check["detail"])

    def test_audit_tests(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "rust_audit_tests")
        self.assertTrue(check["passed"], check["detail"])

    def test_budget_tests(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "rust_budget_tests")
        self.assertTrue(check["passed"], check["detail"])

    def test_rollback_tests(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "rust_rollback_tests")
        self.assertTrue(check["passed"], check["detail"])

    def test_replay_tests(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "rust_replay_tests")
        self.assertTrue(check["passed"], check["detail"])

    def test_degraded_tests(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "rust_degraded_tests")
        self.assertTrue(check["passed"], check["detail"])

    def test_error_tests(self):
        result = checker.run_all()
        check = next(c for c in result["checks"] if c["name"] == "rust_error_tests")
        self.assertTrue(check["passed"], check["detail"])


class TestOverallVerdict(unittest.TestCase):
    def test_all_pass(self):
        result = checker.run_all()
        failing = [c["name"] for c in result["checks"] if not c["passed"]]
        self.assertEqual(result["verdict"], "PASS",
                         f"Failed checks: {failing}")


if __name__ == "__main__":
    unittest.main()
