#!/usr/bin/env python3
"""Unit tests for check_runbook_links.py verification script."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_runbook_links as checker


class TestCheckFileHelper(unittest.TestCase):
    def test_region_runbook_exists(self):
        result = checker.check_file(checker.REGION_RUNBOOK, "region")
        self.assertTrue(result["pass"])

    def test_obligation_runbook_exists(self):
        result = checker.check_file(checker.OBLIGATION_RUNBOOK, "obligation")
        self.assertTrue(result["pass"])

    def test_cancel_runbook_exists(self):
        result = checker.check_file(checker.CANCEL_RUNBOOK, "cancel")
        self.assertTrue(result["pass"])

    def test_dashboard_doc_exists(self):
        result = checker.check_file(checker.DASHBOARD_DOC, "dashboard")
        self.assertTrue(result["pass"])

    def test_alert_map_exists(self):
        result = checker.check_file(checker.ALERT_MAP, "alert map")
        self.assertTrue(result["pass"])

    def test_file_missing(self):
        result = checker.check_file(Path("/nonexistent"), "x")
        self.assertFalse(result["pass"])


class TestCheckSections(unittest.TestCase):
    def test_region_has_all_sections(self):
        results = checker.check_sections("region", checker.REGION_RUNBOOK)
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_obligation_has_all_sections(self):
        results = checker.check_sections("obligation", checker.OBLIGATION_RUNBOOK)
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_cancel_has_all_sections(self):
        results = checker.check_sections("cancel", checker.CANCEL_RUNBOOK)
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_four_required_sections(self):
        self.assertEqual(len(checker.REQUIRED_SECTIONS), 4)


class TestCheckMetrics(unittest.TestCase):
    def test_region_metrics(self):
        results = checker.check_metrics("region", checker.REGION_RUNBOOK, checker.REGION_METRICS)
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")

    def test_obligation_metrics(self):
        results = checker.check_metrics("obligation", checker.OBLIGATION_RUNBOOK, checker.OBLIGATION_METRICS)
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")

    def test_cancel_metrics(self):
        results = checker.check_metrics("cancel", checker.CANCEL_RUNBOOK, checker.CANCEL_METRICS)
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")

    def test_region_metrics_count(self):
        self.assertEqual(len(checker.REGION_METRICS), 3)

    def test_obligation_metrics_count(self):
        self.assertEqual(len(checker.OBLIGATION_METRICS), 4)

    def test_cancel_metrics_count(self):
        self.assertEqual(len(checker.CANCEL_METRICS), 4)


class TestCheckEventCodes(unittest.TestCase):
    def test_region_event_codes(self):
        results = checker.check_event_codes("region", checker.REGION_RUNBOOK, checker.REGION_EVENT_CODES)
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")

    def test_obligation_event_codes(self):
        results = checker.check_event_codes("obligation", checker.OBLIGATION_RUNBOOK, checker.OBLIGATION_EVENT_CODES)
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")

    def test_cancel_event_codes(self):
        results = checker.check_event_codes("cancel", checker.CANCEL_RUNBOOK, checker.CANCEL_EVENT_CODES)
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")


class TestCheckCrossRefs(unittest.TestCase):
    def test_region_cross_refs(self):
        results = checker.check_cross_refs("region", checker.REGION_RUNBOOK, checker.CROSS_REFS["region_quiescence_breach"])
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")

    def test_obligation_cross_refs(self):
        results = checker.check_cross_refs("obligation", checker.OBLIGATION_RUNBOOK, checker.CROSS_REFS["obligation_leak_incident"])
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")

    def test_cancel_cross_refs(self):
        results = checker.check_cross_refs("cancel", checker.CANCEL_RUNBOOK, checker.CROSS_REFS["cancel_timeout_incident"])
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")


class TestCheckAlertReference(unittest.TestCase):
    def test_region_alert(self):
        result = checker.check_alert_reference("region_quiescence_breach", checker.REGION_RUNBOOK)
        self.assertTrue(result["pass"])

    def test_obligation_alert(self):
        result = checker.check_alert_reference("obligation_leak_incident", checker.OBLIGATION_RUNBOOK)
        self.assertTrue(result["pass"])

    def test_cancel_alert(self):
        result = checker.check_alert_reference("cancel_timeout_incident", checker.CANCEL_RUNBOOK)
        self.assertTrue(result["pass"])


class TestCheckSeverity(unittest.TestCase):
    def test_region_severity(self):
        result = checker.check_severity("region_quiescence_breach", checker.REGION_RUNBOOK)
        self.assertTrue(result["pass"])

    def test_obligation_severity(self):
        result = checker.check_severity("obligation_leak_incident", checker.OBLIGATION_RUNBOOK)
        self.assertTrue(result["pass"])

    def test_cancel_severity(self):
        result = checker.check_severity("cancel_timeout_incident", checker.CANCEL_RUNBOOK)
        self.assertTrue(result["pass"])


class TestCheckReplayLabReference(unittest.TestCase):
    def test_region_replay(self):
        result = checker.check_replay_lab_reference("region", checker.REGION_RUNBOOK)
        self.assertTrue(result["pass"])

    def test_obligation_replay(self):
        result = checker.check_replay_lab_reference("obligation", checker.OBLIGATION_RUNBOOK)
        self.assertTrue(result["pass"])

    def test_cancel_replay(self):
        result = checker.check_replay_lab_reference("cancel", checker.CANCEL_RUNBOOK)
        self.assertTrue(result["pass"])


class TestCheckMetricsInDashboard(unittest.TestCase):
    def test_region_metrics_in_dashboard(self):
        results = checker.check_metrics_in_dashboard("region", checker.REGION_METRICS)
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")

    def test_obligation_metrics_in_dashboard(self):
        results = checker.check_metrics_in_dashboard("obligation", checker.OBLIGATION_METRICS)
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")

    def test_cancel_metrics_in_dashboard(self):
        results = checker.check_metrics_in_dashboard("cancel", checker.CANCEL_METRICS)
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}")


class TestCheckAlertMapReferences(unittest.TestCase):
    def test_all_alerts_reference_bd_1f8m(self):
        results = checker.check_alert_map_references_runbooks()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_six_alerts_in_map(self):
        results = checker.check_alert_map_references_runbooks()
        self.assertEqual(len(results), 6)


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
        self.assertEqual(result["bead_id"], "bd-1f8m")

    def test_check_count_reasonable(self):
        result = checker.run_checks()
        self.assertGreaterEqual(result["summary"]["total"], 60)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = checker.self_test()
        self.assertTrue(ok)

    def test_self_test_returns_checks(self):
        ok, checks = checker.self_test()
        self.assertIsInstance(checks, list)
        self.assertGreater(len(checks), 0)


class TestRequiredConstants(unittest.TestCase):
    def test_runbooks_count(self):
        self.assertEqual(len(checker.RUNBOOKS), 3)

    def test_required_sections_count(self):
        self.assertEqual(len(checker.REQUIRED_SECTIONS), 4)

    def test_alert_names_count(self):
        self.assertEqual(len(checker.ALERT_NAMES), 3)

    def test_severity_count(self):
        self.assertEqual(len(checker.SEVERITY), 3)


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_checks()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_runbook_links.py"), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["verdict"], "PASS")

    def test_cli_human(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_runbook_links.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
