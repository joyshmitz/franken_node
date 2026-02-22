#!/usr/bin/env python3
"""Unit tests for check_control_idempotency_adoption.py (bd-1cwp)."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_control_idempotency_adoption as cia


class TestConstants(unittest.TestCase):
    def test_four_retryable_requests(self):
        self.assertEqual(len(cia.RETRYABLE_REQUESTS), 4)

    def test_one_non_retryable_request(self):
        self.assertEqual(len(cia.NON_RETRYABLE_REQUESTS), 1)

    def test_fencing_not_retryable(self):
        self.assertIn("fencing_acquire", cia.NON_RETRYABLE_REQUESTS)

    def test_health_probe_retryable(self):
        self.assertIn("health_probe", cia.RETRYABLE_REQUESTS)


class TestCheckKeyDerivationExists(unittest.TestCase):
    def test_passes(self):
        result = cia.check_key_derivation_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CIA-KEY")


class TestCheckDedupStoreExists(unittest.TestCase):
    def test_passes(self):
        result = cia.check_dedup_store_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CIA-DEDUP")


class TestCheckAdoptionDocExists(unittest.TestCase):
    def test_passes(self):
        result = cia.check_adoption_doc_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CIA-DOC")


class TestCheckAdoptionReportExists(unittest.TestCase):
    def test_passes(self):
        result = cia.check_adoption_report_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CIA-REPORT")

    def test_report_has_bead(self):
        data = json.loads(cia.ADOPTION_REPORT.read_text())
        self.assertEqual(data["bead"], "bd-1cwp")

    def test_report_has_adoption_status(self):
        data = json.loads(cia.ADOPTION_REPORT.read_text())
        self.assertEqual(data["adoption_status"], "documented")


class TestCheckRetryableRequestsDocumented(unittest.TestCase):
    def test_passes(self):
        result = cia.check_retryable_requests_documented()
        self.assertEqual(result["status"], "PASS")

    def test_no_missing(self):
        result = cia.check_retryable_requests_documented()
        self.assertEqual(result["details"]["missing"], [])


class TestCheckDeriveKeyFunction(unittest.TestCase):
    def test_passes(self):
        result = cia.check_derive_key_function()
        self.assertEqual(result["status"], "PASS")


class TestCheckDedupContractDocumented(unittest.TestCase):
    def test_passes(self):
        result = cia.check_dedup_contract_documented()
        self.assertEqual(result["status"], "PASS")

    def test_no_missing_sections(self):
        result = cia.check_dedup_contract_documented()
        self.assertEqual(result["details"]["missing_sections"], [])


class TestCheckNoCustomIdempotency(unittest.TestCase):
    def test_passes(self):
        result = cia.check_no_custom_idempotency()
        self.assertEqual(result["status"], "PASS")

    def test_no_violations(self):
        result = cia.check_no_custom_idempotency()
        self.assertEqual(result["details"]["violations"], [])


class TestCheckReportRetryableCount(unittest.TestCase):
    def test_passes(self):
        result = cia.check_report_retryable_count()
        self.assertEqual(result["status"], "PASS")

    def test_four_retryable(self):
        result = cia.check_report_retryable_count()
        self.assertEqual(result["details"]["count"], 4)


class TestCheckEventCodesDocumented(unittest.TestCase):
    def test_passes(self):
        result = cia.check_event_codes_documented()
        self.assertEqual(result["status"], "PASS")

    def test_no_missing_codes(self):
        result = cia.check_event_codes_documented()
        self.assertEqual(result["details"]["missing"], [])


class TestCheckInvariantsDocumented(unittest.TestCase):
    def test_passes(self):
        result = cia.check_invariants_documented()
        self.assertEqual(result["status"], "PASS")


class TestSelfTest(unittest.TestCase):
    def test_verdict_pass(self):
        result = cia.self_test()
        self.assertEqual(result["verdict"], "PASS")

    def test_all_checks_present(self):
        result = cia.self_test()
        self.assertGreaterEqual(result["summary"]["total_checks"], 15)

    def test_no_failures(self):
        result = cia.self_test()
        self.assertEqual(result["summary"]["failing_checks"], 0)

    def test_bead_field(self):
        result = cia.self_test()
        self.assertEqual(result["bead"], "bd-1cwp")

    def test_section_field(self):
        result = cia.self_test()
        self.assertEqual(result["section"], "10.15")


if __name__ == "__main__":
    unittest.main()
