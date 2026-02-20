#!/usr/bin/env python3
"""Unit tests for check_policy_change_workflow.py verification script."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_policy_change_workflow as checker


class TestCheckFileHelper(unittest.TestCase):
    def test_file_exists(self):
        result = checker.check_file(checker.IMPL, "implementation")
        self.assertTrue(result["pass"])

    def test_file_missing(self):
        result = checker.check_file(Path("/nonexistent/file.rs"), "missing")
        self.assertFalse(result["pass"])

    def test_detail_on_exists(self):
        result = checker.check_file(checker.IMPL, "implementation")
        self.assertIn("exists:", result["detail"])

    def test_detail_on_missing(self):
        result = checker.check_file(Path("/nonexistent"), "x")
        self.assertIn("MISSING", result["detail"])


class TestCheckContentHelper(unittest.TestCase):
    def test_found(self):
        results = checker.check_content(checker.IMPL, ["pub enum RiskAssessment"], "type")
        self.assertTrue(results[0]["pass"])

    def test_not_found(self):
        results = checker.check_content(checker.IMPL, ["NONEXISTENT_XYZ"], "type")
        self.assertFalse(results[0]["pass"])

    def test_missing_file(self):
        results = checker.check_content(Path("/nonexistent"), ["pattern"], "cat")
        self.assertFalse(results[0]["pass"])

    def test_multiple(self):
        results = checker.check_content(
            checker.IMPL,
            ["pub enum RiskAssessment", "pub enum ProposalState"],
            "type",
        )
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["pass"] for r in results))


class TestCheckModuleRegistered(unittest.TestCase):
    def test_registered(self):
        result = checker.check_module_registered()
        self.assertTrue(result["pass"])


class TestCheckTestCount(unittest.TestCase):
    def test_minimum_20(self):
        result = checker.check_test_count()
        self.assertTrue(result["pass"])
        count = int(result["detail"].split()[0])
        self.assertGreaterEqual(count, 20)


class TestCheckSerdeDerive(unittest.TestCase):
    def test_serde(self):
        result = checker.check_serde_derives()
        self.assertTrue(result["pass"])


class TestCheckHashChain(unittest.TestCase):
    def test_hash_chain_checks(self):
        results = checker.check_hash_chain()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_sha256_present(self):
        results = checker.check_hash_chain()
        sha_check = [r for r in results if "SHA-256" in r["check"]]
        self.assertTrue(len(sha_check) > 0)
        self.assertTrue(sha_check[0]["pass"])


class TestCheckRoleSeparation(unittest.TestCase):
    def test_role_separation_checks(self):
        results = checker.check_role_separation()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")


class TestCheckRollbackMechanism(unittest.TestCase):
    def test_rollback_checks(self):
        results = checker.check_rollback_mechanism()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")


class TestCheckSpecInvariants(unittest.TestCase):
    def test_all_invariants(self):
        results = checker.check_spec_invariants()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_invariant_count(self):
        self.assertGreaterEqual(len(checker.INVARIANTS), 8)


class TestRunChecks(unittest.TestCase):
    def test_full_run(self):
        result = checker.run_checks()
        self.assertIn("checks", result)
        self.assertIn("summary", result)

    def test_all_checks_pass(self):
        result = checker.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(
            len(failing), 0,
            f"Failing checks: {json.dumps(failing, indent=2)}",
        )

    def test_verdict_is_pass(self):
        result = checker.run_checks()
        self.assertEqual(result["verdict"], "PASS")

    def test_title_field(self):
        result = checker.run_checks()
        self.assertIn("approval", result["title"].lower())

    def test_test_count_field(self):
        result = checker.run_checks()
        count = int(result["test_count"])
        self.assertGreaterEqual(count, 20)

    def test_check_count_reasonable(self):
        result = checker.run_checks()
        self.assertGreaterEqual(result["summary"]["total"], 70)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = checker.self_test()
        self.assertTrue(ok)

    def test_self_test_returns_checks(self):
        ok, checks = checker.self_test()
        self.assertIsInstance(checks, list)
        self.assertGreater(len(checks), 0)


class TestRequiredConstants(unittest.TestCase):
    def test_types_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_TYPES), 10)

    def test_methods_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_METHODS), 9)

    def test_event_codes_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 8)

    def test_error_codes_count(self):
        self.assertEqual(len(checker.ERROR_CODES), 7)

    def test_invariants_count(self):
        self.assertEqual(len(checker.INVARIANTS), 8)

    def test_states_count(self):
        self.assertEqual(len(checker.PROPOSAL_STATES), 6)

    def test_required_tests_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_TESTS), 20)


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_checks()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_policy_change_workflow.py"), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["verdict"], "PASS")

    def test_cli_human(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_policy_change_workflow.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
