#!/usr/bin/env python3
"""Unit tests for check_substrate_overhead.py verification script."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_substrate_overhead as checker


class TestCheckFileHelper(unittest.TestCase):
    def test_impl_exists(self):
        result = checker.check_file(checker.IMPL, "perf test")
        self.assertTrue(result["pass"])

    def test_spec_exists(self):
        result = checker.check_file(checker.SPEC, "spec contract")
        self.assertTrue(result["pass"])

    def test_overhead_csv_exists(self):
        result = checker.check_file(checker.OVERHEAD_CSV, "overhead CSV")
        self.assertTrue(result["pass"])

    def test_file_missing(self):
        result = checker.check_file(Path("/nonexistent"), "x")
        self.assertFalse(result["pass"])

    def test_detail_on_exists(self):
        result = checker.check_file(checker.IMPL, "perf test")
        self.assertIn("exists:", result["detail"])

    def test_detail_on_missing(self):
        result = checker.check_file(Path("/nonexistent"), "x")
        self.assertIn("MISSING", result["detail"])


class TestCheckContentHelper(unittest.TestCase):
    def test_found_in_impl(self):
        results = checker.check_content(
            checker.IMPL,
            ["pub enum Substrate"],
            "type",
        )
        self.assertTrue(results[0]["pass"])

    def test_not_found(self):
        results = checker.check_content(
            checker.IMPL,
            ["NONEXISTENT_XYZ_123"],
            "type",
        )
        self.assertFalse(results[0]["pass"])

    def test_missing_file(self):
        results = checker.check_content(Path("/nonexistent"), ["pattern"], "cat")
        self.assertFalse(results[0]["pass"])

    def test_multiple(self):
        results = checker.check_content(
            checker.IMPL,
            ["pub enum Substrate", "pub struct Operation"],
            "type",
        )
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["pass"] for r in results))


class TestCheckImplTestCount(unittest.TestCase):
    def test_minimum_35(self):
        result = checker.check_impl_test_count()
        self.assertTrue(result["pass"])
        count = int(result["detail"].split()[0])
        self.assertGreaterEqual(count, 35)


class TestCheckSerdeDerive(unittest.TestCase):
    def test_serde(self):
        result = checker.check_serde_derives()
        self.assertTrue(result["pass"])


class TestCheckOverheadCsv(unittest.TestCase):
    def test_csv_all_pass(self):
        results = checker.check_overhead_csv()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_all_operations_in_csv(self):
        results = checker.check_overhead_csv()
        op_checks = [r for r in results if "/" in r.get("check", "")]
        self.assertEqual(len(op_checks), 8)

    def test_all_pass_at_p95(self):
        results = checker.check_overhead_csv()
        pass_check = [r for r in results if "all pass at p95" in r["check"]]
        self.assertTrue(len(pass_check) > 0)
        self.assertTrue(pass_check[0]["pass"])

    def test_no_regressions(self):
        results = checker.check_overhead_csv()
        reg_check = [r for r in results if "no regressions" in r["check"]]
        self.assertTrue(len(reg_check) > 0)
        self.assertTrue(reg_check[0]["pass"])

    def test_baselines_present(self):
        results = checker.check_overhead_csv()
        bl_check = [r for r in results if "baseline data" in r["check"]]
        self.assertTrue(len(bl_check) > 0)
        self.assertTrue(bl_check[0]["pass"])


class TestCheckSpecContent(unittest.TestCase):
    def test_spec_all_pass(self):
        results = checker.check_spec_content()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_substrates_documented(self):
        results = checker.check_spec_content()
        sub_checks = [r for r in results if "substrate" in r["check"]]
        self.assertEqual(len(sub_checks), 4)

    def test_event_codes_documented(self):
        results = checker.check_spec_content()
        ec_checks = [r for r in results if "event code" in r["check"]]
        self.assertEqual(len(ec_checks), 5)

    def test_invariants_documented(self):
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

    def test_title_field(self):
        result = checker.run_checks()
        self.assertIn("overhead", result["title"].lower())

    def test_test_count_field(self):
        result = checker.run_checks()
        count = int(result["test_count"])
        self.assertGreaterEqual(count, 35)

    def test_check_count_reasonable(self):
        result = checker.run_checks()
        self.assertGreaterEqual(result["summary"]["total"], 80)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = checker.self_test()
        self.assertTrue(ok)

    def test_self_test_returns_checks(self):
        ok, checks = checker.self_test()
        self.assertIsInstance(checks, list)
        self.assertGreater(len(checks), 0)


class TestRequiredConstants(unittest.TestCase):
    def test_substrates_count(self):
        self.assertEqual(len(checker.SUBSTRATES), 4)

    def test_operations_count(self):
        self.assertEqual(len(checker.OPERATIONS), 8)

    def test_event_codes_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 5)

    def test_invariants_count(self):
        self.assertEqual(len(checker.INVARIANTS), 4)

    def test_types_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_TYPES), 6)

    def test_methods_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_METHODS), 15)

    def test_tests_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_TESTS), 35)


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_checks()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_substrate_overhead.py"), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["verdict"], "PASS")

    def test_cli_human(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_substrate_overhead.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
