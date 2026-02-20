#!/usr/bin/env python3
"""Unit tests for check_non_negotiable_constraints.py verification script."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_non_negotiable_constraints as checker


class TestCheckFileHelper(unittest.TestCase):
    def test_constraint_doc_exists(self):
        result = checker.check_file(checker.CONSTRAINT_DOC, "constraint doc")
        self.assertTrue(result["pass"])

    def test_waiver_registry_exists(self):
        result = checker.check_file(checker.WAIVER_REGISTRY, "waiver registry")
        self.assertTrue(result["pass"])

    def test_spec_exists(self):
        result = checker.check_file(checker.SPEC, "spec")
        self.assertTrue(result["pass"])

    def test_file_missing(self):
        result = checker.check_file(Path("/nonexistent"), "x")
        self.assertFalse(result["pass"])


class TestCheckConstraintDoc(unittest.TestCase):
    def test_all_checks_pass(self):
        results = checker.check_constraint_doc()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_all_13_constraints_documented(self):
        results = checker.check_constraint_doc()
        constraint_checks = [r for r in results if r["check"].startswith("constraint C-")]
        self.assertEqual(len(constraint_checks), 13)
        for r in constraint_checks:
            self.assertTrue(r["pass"])

    def test_all_violation_codes(self):
        results = checker.check_constraint_doc()
        violation_checks = [r for r in results if "violation code" in r["check"]]
        self.assertEqual(len(violation_checks), 13)
        for r in violation_checks:
            self.assertTrue(r["pass"])

    def test_required_sections(self):
        results = checker.check_constraint_doc()
        section_checks = [r for r in results if r["check"].startswith("doc section:")]
        self.assertEqual(len(section_checks), 3)

    def test_fix_instructions(self):
        results = checker.check_constraint_doc()
        fix_check = [r for r in results if "fix instructions" in r["check"]]
        self.assertTrue(len(fix_check) > 0)
        self.assertTrue(fix_check[0]["pass"])


class TestCheckWaiverRegistry(unittest.TestCase):
    def test_all_checks_pass(self):
        results = checker.check_waiver_registry()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_valid_json(self):
        results = checker.check_waiver_registry()
        json_check = [r for r in results if "valid JSON" in r["check"]]
        self.assertTrue(len(json_check) > 0)
        self.assertTrue(json_check[0]["pass"])

    def test_schema_version(self):
        results = checker.check_waiver_registry()
        sv_check = [r for r in results if "schema_version" in r["check"]]
        self.assertTrue(len(sv_check) > 0)
        self.assertTrue(sv_check[0]["pass"])


class TestCheckSpecContent(unittest.TestCase):
    def test_all_checks_pass(self):
        results = checker.check_spec_content()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_event_codes(self):
        results = checker.check_spec_content()
        ec_checks = [r for r in results if "event_code" in r["check"]]
        self.assertEqual(len(ec_checks), 4)

    def test_invariants(self):
        results = checker.check_spec_content()
        inv_checks = [r for r in results if "invariant" in r["check"]]
        self.assertEqual(len(inv_checks), 4)


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

    def test_bead_id(self):
        result = checker.run_checks()
        self.assertEqual(result["bead_id"], "bd-28wj")

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
    def test_constraint_ids_count(self):
        self.assertEqual(len(checker.CONSTRAINT_IDS), 13)

    def test_event_codes_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 4)

    def test_invariants_count(self):
        self.assertEqual(len(checker.INVARIANTS), 4)

    def test_keywords_count(self):
        self.assertEqual(len(checker.CONSTRAINT_KEYWORDS), 13)


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_checks()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_non_negotiable_constraints.py"), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["verdict"], "PASS")

    def test_cli_human(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_non_negotiable_constraints.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
