#!/usr/bin/env python3
"""Unit tests for check_control_cancel_injection.py (bd-3tpg)."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_control_cancel_injection as cci


class TestConstants(unittest.TestCase):
    def test_six_required_workflows(self):
        self.assertEqual(len(cci.REQUIRED_WORKFLOWS), 6)

    def test_five_event_codes(self):
        self.assertEqual(len(cci.REQUIRED_EVENT_CODES), 5)

    def test_eight_invariants(self):
        self.assertEqual(len(cci.REQUIRED_INVARIANTS), 8)

    def test_min_injection_points(self):
        self.assertGreaterEqual(cci.MIN_INJECTION_POINTS, 30)

    def test_workflow_names(self):
        expected = [
            "connector_lifecycle",
            "rollout_transition",
            "quarantine_promotion",
            "migration_orchestration",
            "fencing_acquire",
            "health_gate_evaluation",
        ]
        self.assertEqual(cci.REQUIRED_WORKFLOWS, expected)


class TestCheckAdoptionDocExists(unittest.TestCase):
    def test_passes(self):
        result = cci.check_adoption_doc_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CCI-001")

    def test_has_path(self):
        result = cci.check_adoption_doc_exists()
        self.assertIn("path", result["details"])


class TestCheckAdoptionDocSections(unittest.TestCase):
    def test_passes(self):
        result = cci.check_adoption_doc_sections()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CCI-002")

    def test_no_missing_sections(self):
        result = cci.check_adoption_doc_sections()
        self.assertEqual(result["details"]["missing_sections"], [])


class TestCheckWorkflowsDocumented(unittest.TestCase):
    def test_passes(self):
        result = cci.check_workflows_documented()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CCI-003")

    def test_no_missing(self):
        result = cci.check_workflows_documented()
        self.assertEqual(result["details"]["missing"], [])

    def test_total_six(self):
        result = cci.check_workflows_documented()
        self.assertEqual(result["details"]["total"], 6)


class TestCheckReportExists(unittest.TestCase):
    def test_passes(self):
        result = cci.check_report_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CCI-004")

    def test_bead_field(self):
        data = json.loads(cci.ADOPTION_REPORT.read_text())
        self.assertEqual(data["bead"], "bd-3tpg")

    def test_section_field(self):
        data = json.loads(cci.ADOPTION_REPORT.read_text())
        self.assertEqual(data["section"], "10.15")

    def test_adoption_status(self):
        data = json.loads(cci.ADOPTION_REPORT.read_text())
        self.assertEqual(data["adoption_status"], "documented")


class TestCheckReportWorkflows(unittest.TestCase):
    def test_passes(self):
        result = cci.check_report_workflows()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CCI-005")

    def test_six_workflows(self):
        result = cci.check_report_workflows()
        self.assertEqual(result["details"]["workflow_count"], 6)

    def test_all_pass(self):
        result = cci.check_report_workflows()
        self.assertTrue(result["details"]["all_pass"])


class TestCheckReportInjectionPoints(unittest.TestCase):
    def test_passes(self):
        result = cci.check_report_injection_points()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CCI-006")

    def test_total_at_least_30(self):
        result = cci.check_report_injection_points()
        self.assertGreaterEqual(result["details"]["total_injection_points"], 30)

    def test_zero_failures(self):
        result = cci.check_report_injection_points()
        self.assertEqual(result["details"]["total_failures"], 0)


class TestCheckCancellationInjectionSource(unittest.TestCase):
    def test_passes(self):
        result = cci.check_cancellation_injection_source()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CCI-007")


class TestCheckCancellationInjectionFramework(unittest.TestCase):
    def test_passes(self):
        result = cci.check_cancellation_injection_framework()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CCI-008")

    def test_has_framework(self):
        result = cci.check_cancellation_injection_framework()
        self.assertTrue(result["details"]["has_framework"])

    def test_has_matrix(self):
        result = cci.check_cancellation_injection_framework()
        self.assertTrue(result["details"]["has_matrix"])


class TestCheckEventCodesDocumented(unittest.TestCase):
    def test_passes(self):
        result = cci.check_event_codes_documented()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CCI-009")

    def test_no_missing_codes(self):
        result = cci.check_event_codes_documented()
        self.assertEqual(result["details"]["missing"], [])


class TestCheckInvariantsDocumented(unittest.TestCase):
    def test_passes(self):
        result = cci.check_invariants_documented()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CCI-010")

    def test_no_missing(self):
        result = cci.check_invariants_documented()
        self.assertEqual(result["details"]["missing"], [])


class TestCheckSpecContractExists(unittest.TestCase):
    def test_passes(self):
        result = cci.check_spec_contract_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CCI-011")


class TestCheckTestFileExists(unittest.TestCase):
    def test_passes(self):
        result = cci.check_test_file_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CCI-012")


class TestCheckEvidenceFileExists(unittest.TestCase):
    def test_passes(self):
        result = cci.check_evidence_file_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CCI-013")


class TestCheckSummaryFileExists(unittest.TestCase):
    def test_passes(self):
        result = cci.check_summary_file_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CCI-014")


class TestCheckNoCustomInjectionLogic(unittest.TestCase):
    def test_passes(self):
        result = cci.check_no_custom_injection_logic()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CCI-015")

    def test_no_violations(self):
        result = cci.check_no_custom_injection_logic()
        self.assertEqual(result["details"]["violations"], [])


class TestSelfTest(unittest.TestCase):
    def test_verdict_pass(self):
        result = cci.self_test()
        self.assertEqual(result["verdict"], "PASS")

    def test_all_checks_present(self):
        result = cci.self_test()
        self.assertEqual(result["summary"]["total_checks"], 15)

    def test_no_failures(self):
        result = cci.self_test()
        self.assertEqual(result["summary"]["failing_checks"], 0)

    def test_bead_field(self):
        result = cci.self_test()
        self.assertEqual(result["bead"], "bd-3tpg")

    def test_section_field(self):
        result = cci.self_test()
        self.assertEqual(result["section"], "10.15")

    def test_gate_name(self):
        result = cci.self_test()
        self.assertEqual(result["gate"], "control_cancel_injection_verification")

    def test_has_timestamp(self):
        result = cci.self_test()
        self.assertIn("timestamp", result)

    def test_checks_have_ids(self):
        result = cci.self_test()
        for c in result["checks"]:
            self.assertIn("id", c)
            self.assertTrue(c["id"].startswith("CCI-"))

    def test_checks_have_status(self):
        result = cci.self_test()
        for c in result["checks"]:
            self.assertIn(c["status"], ("PASS", "FAIL"))

    def test_checks_have_details(self):
        result = cci.self_test()
        for c in result["checks"]:
            self.assertIn("details", c)


if __name__ == "__main__":
    unittest.main()
