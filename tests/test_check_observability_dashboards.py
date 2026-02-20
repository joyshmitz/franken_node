#!/usr/bin/env python3
"""Unit tests for check_observability_dashboards.py verification script."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_observability_dashboards as checker


class TestCheckFileHelper(unittest.TestCase):
    def test_doc_exists(self):
        result = checker.check_file(checker.DOC, "dashboard doc")
        self.assertTrue(result["pass"])

    def test_snapshot_exists(self):
        result = checker.check_file(checker.SNAPSHOT, "snapshot")
        self.assertTrue(result["pass"])

    def test_alert_map_exists(self):
        result = checker.check_file(checker.ALERT_MAP, "alert map")
        self.assertTrue(result["pass"])

    def test_file_missing(self):
        result = checker.check_file(Path("/nonexistent"), "x")
        self.assertFalse(result["pass"])


class TestCheckDocContent(unittest.TestCase):
    def test_all_keywords_found(self):
        results = checker.check_doc_content()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_event_codes_in_doc(self):
        results = checker.check_doc_content()
        ec_checks = [r for r in results if "event_code" in r["check"]]
        self.assertEqual(len(ec_checks), 4)
        for r in ec_checks:
            self.assertTrue(r["pass"])

    def test_invariants_in_doc(self):
        results = checker.check_doc_content()
        inv_checks = [r for r in results if "invariant" in r["check"]]
        self.assertEqual(len(inv_checks), 4)
        for r in inv_checks:
            self.assertTrue(r["pass"])


class TestCheckDashboardSnapshot(unittest.TestCase):
    def test_snapshot_checks_pass(self):
        results = checker.check_dashboard_snapshot()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_all_categories_present(self):
        results = checker.check_dashboard_snapshot()
        cat_checks = [r for r in results if "snapshot panel" in r["check"]]
        self.assertEqual(len(cat_checks), 4)
        for r in cat_checks:
            self.assertTrue(r["pass"])

    def test_fn_prefix(self):
        results = checker.check_dashboard_snapshot()
        prefix_check = [r for r in results if "fn_ metric prefix" in r["check"]]
        self.assertTrue(len(prefix_check) > 0)
        self.assertTrue(prefix_check[0]["pass"])


class TestCheckAlertPolicyMap(unittest.TestCase):
    def test_alert_map_checks_pass(self):
        results = checker.check_alert_policy_map()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_required_alerts_present(self):
        results = checker.check_alert_policy_map()
        alert_checks = [r for r in results if r["check"].startswith("alert:")]
        self.assertEqual(len(alert_checks), 4)
        for r in alert_checks:
            self.assertTrue(r["pass"])

    def test_all_alerts_have_runbook(self):
        results = checker.check_alert_policy_map()
        runbook_check = [r for r in results if "runbook" in r["check"]]
        self.assertTrue(len(runbook_check) > 0)
        self.assertTrue(runbook_check[0]["pass"])


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

    def test_check_count_reasonable(self):
        result = checker.run_checks()
        self.assertGreaterEqual(result["summary"]["total"], 30)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = checker.self_test()
        self.assertTrue(ok)

    def test_self_test_returns_checks(self):
        ok, checks = checker.self_test()
        self.assertIsInstance(checks, list)
        self.assertGreater(len(checks), 0)


class TestRequiredConstants(unittest.TestCase):
    def test_categories_count(self):
        self.assertEqual(len(checker.DASHBOARD_CATEGORIES), 4)

    def test_event_codes_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 4)

    def test_invariants_count(self):
        self.assertEqual(len(checker.INVARIANTS), 4)

    def test_alert_names_count(self):
        self.assertEqual(len(checker.ALERT_NAMES), 4)


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_checks()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_observability_dashboards.py"), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["verdict"], "PASS")

    def test_cli_human(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_observability_dashboards.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
