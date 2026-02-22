#!/usr/bin/env python3
"""Unit tests for check_epoch_barrier_adoption.py (bd-1hbw)."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_epoch_barrier_adoption as eba


class TestCheckBarrierSourceExists(unittest.TestCase):
    def test_passes(self):
        result = eba.check_barrier_source_exists()
        self.assertEqual(result["status"], "PASS")


class TestCheckBarrierModWired(unittest.TestCase):
    def test_passes(self):
        result = eba.check_barrier_mod_wired()
        self.assertEqual(result["status"], "PASS")


class TestCheckAdoptionDocExists(unittest.TestCase):
    def test_passes(self):
        result = eba.check_adoption_doc_exists()
        self.assertEqual(result["status"], "PASS")


class TestCheckTranscriptExists(unittest.TestCase):
    def test_passes(self):
        result = eba.check_transcript_exists()
        self.assertEqual(result["status"], "PASS")

    def test_has_bead(self):
        data = json.loads(eba.TRANSCRIPT.read_text())
        self.assertEqual(data["bead"], "bd-1hbw")


class TestCheckParticipantsDocumented(unittest.TestCase):
    def test_passes(self):
        result = eba.check_participants_documented()
        self.assertEqual(result["status"], "PASS")

    def test_no_missing(self):
        result = eba.check_participants_documented()
        self.assertEqual(result["details"]["missing"], [])


class TestCheckAbortSemantics(unittest.TestCase):
    def test_passes(self):
        result = eba.check_abort_semantics_documented()
        self.assertEqual(result["status"], "PASS")


class TestCheckEventCodes(unittest.TestCase):
    def test_passes(self):
        result = eba.check_event_codes_documented()
        self.assertEqual(result["status"], "PASS")

    def test_no_missing(self):
        result = eba.check_event_codes_documented()
        self.assertEqual(result["details"]["missing"], [])


class TestCheckInvariants(unittest.TestCase):
    def test_passes(self):
        result = eba.check_invariants_documented()
        self.assertEqual(result["status"], "PASS")


class TestCheckTranscriptParticipantsCount(unittest.TestCase):
    def test_passes(self):
        result = eba.check_transcript_participants_count()
        self.assertEqual(result["status"], "PASS")

    def test_four_participants(self):
        result = eba.check_transcript_participants_count()
        self.assertEqual(result["details"]["count"], 4)


class TestCheckTranscriptTestScenarios(unittest.TestCase):
    def test_passes(self):
        result = eba.check_transcript_test_scenarios()
        self.assertEqual(result["status"], "PASS")


class TestCheckSpecContractExists(unittest.TestCase):
    def test_passes(self):
        result = eba.check_spec_contract_exists()
        self.assertEqual(result["status"], "PASS")


class TestCheckTestFileExists(unittest.TestCase):
    def test_passes(self):
        result = eba.check_test_file_exists()
        self.assertEqual(result["status"], "PASS")


class TestCheckNoCustomBarrier(unittest.TestCase):
    def test_passes(self):
        result = eba.check_no_custom_barrier()
        self.assertEqual(result["status"], "PASS")

    def test_no_violations(self):
        result = eba.check_no_custom_barrier()
        self.assertEqual(result["details"]["violations"], [])


class TestSelfTest(unittest.TestCase):
    def test_verdict_pass(self):
        result = eba.self_test()
        self.assertEqual(result["verdict"], "PASS")

    def test_all_checks_present(self):
        result = eba.self_test()
        self.assertGreaterEqual(result["summary"]["total_checks"], 13)

    def test_no_failures(self):
        result = eba.self_test()
        self.assertEqual(result["summary"]["failing_checks"], 0)

    def test_bead_field(self):
        result = eba.self_test()
        self.assertEqual(result["bead"], "bd-1hbw")

    def test_section_field(self):
        result = eba.self_test()
        self.assertEqual(result["section"], "10.15")


if __name__ == "__main__":
    unittest.main()
