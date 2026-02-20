#!/usr/bin/env python3
"""Unit tests for scripts/check_build_program.py (bd-3hig)."""

import os
import sys
import unittest

# Ensure scripts/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import check_build_program as cb


class TestFilesExist(unittest.TestCase):
    """Test that required files are verified."""

    def test_required_files_count(self):
        self.assertEqual(len(cb.REQUIRED_FILES), 2)

    def test_spec_contract_in_list(self):
        self.assertTrue(any("bd-3hig_contract.md" in f for f in cb.REQUIRED_FILES))

    def test_governance_doc_in_list(self):
        self.assertTrue(any("build_program.md" in f for f in cb.REQUIRED_FILES))

    def test_check_produces_results(self):
        cb.RESULTS.clear()
        cb.check_files_exist()
        self.assertEqual(len(cb.RESULTS), 2)
        for r in cb.RESULTS:
            self.assertIn("file_exists:", r["check"])


class TestFiveTracks(unittest.TestCase):
    """Test that all five tracks are checked."""

    def test_tracks_count(self):
        self.assertEqual(len(cb.TRACKS), 5)

    def test_track_names(self):
        expected = ["Track-A", "Track-B", "Track-C", "Track-D", "Track-E"]
        self.assertEqual(cb.TRACKS, expected)

    def test_check_produces_five_results(self):
        cb.RESULTS.clear()
        cb.check_five_tracks()
        self.assertEqual(len(cb.RESULTS), 5)
        for r in cb.RESULTS:
            self.assertIn("track_documented:", r["check"])


class TestExitGates(unittest.TestCase):
    """Test that exit gates are checked for each track."""

    def test_check_produces_five_results(self):
        cb.RESULTS.clear()
        cb.check_exit_gates()
        self.assertEqual(len(cb.RESULTS), 5)
        for r in cb.RESULTS:
            self.assertIn("exit_gate:", r["check"])

    def test_all_tracks_have_exit_gates(self):
        cb.RESULTS.clear()
        cb.check_exit_gates()
        for r in cb.RESULTS:
            self.assertTrue(r["passed"], f"Exit gate missing for {r['check']}")


class TestEnhancementMaps(unittest.TestCase):
    """Test that all 15 enhancement maps are checked."""

    def test_maps_count(self):
        self.assertEqual(len(cb.ENHANCEMENT_MAPS), 15)

    def test_maps_range(self):
        self.assertEqual(cb.ENHANCEMENT_MAPS[0], "9A")
        self.assertEqual(cb.ENHANCEMENT_MAPS[14], "9O")

    def test_check_produces_fifteen_results(self):
        cb.RESULTS.clear()
        cb.check_enhancement_maps()
        self.assertEqual(len(cb.RESULTS), 15)
        for r in cb.RESULTS:
            self.assertIn("enhancement_map:", r["check"])

    def test_all_maps_found(self):
        cb.RESULTS.clear()
        cb.check_enhancement_maps()
        for r in cb.RESULTS:
            self.assertTrue(r["passed"], f"Enhancement map missing: {r['check']}")


class TestEventCodes(unittest.TestCase):
    """Test that event codes BLD-001 through BLD-004 are checked."""

    def test_event_codes_count(self):
        self.assertEqual(len(cb.EVENT_CODES), 4)

    def test_event_codes_values(self):
        expected = ["BLD-001", "BLD-002", "BLD-003", "BLD-004"]
        self.assertEqual(cb.EVENT_CODES, expected)

    def test_check_produces_four_results(self):
        cb.RESULTS.clear()
        cb.check_event_codes()
        self.assertEqual(len(cb.RESULTS), 4)
        for r in cb.RESULTS:
            self.assertIn("event_code:", r["check"])

    def test_all_codes_found(self):
        cb.RESULTS.clear()
        cb.check_event_codes()
        for r in cb.RESULTS:
            self.assertTrue(r["passed"], f"Event code missing: {r['check']}")


class TestInvariants(unittest.TestCase):
    """Test that invariants are checked."""

    def test_invariants_count(self):
        self.assertEqual(len(cb.INVARIANTS), 4)

    def test_invariant_names(self):
        expected = ["INV-BLD-TRACKS", "INV-BLD-MAPS", "INV-BLD-EXIT", "INV-BLD-TRACE"]
        self.assertEqual(cb.INVARIANTS, expected)

    def test_check_produces_four_results(self):
        cb.RESULTS.clear()
        cb.check_invariants()
        self.assertEqual(len(cb.RESULTS), 4)
        for r in cb.RESULTS:
            self.assertIn("invariant:", r["check"])

    def test_all_invariants_found(self):
        cb.RESULTS.clear()
        cb.check_invariants()
        for r in cb.RESULTS:
            self.assertTrue(r["passed"], f"Invariant missing: {r['check']}")


class TestRunAll(unittest.TestCase):
    """Test the run_all() function."""

    def test_run_all_returns_dict(self):
        result = cb.run_all()
        self.assertIsInstance(result, dict)

    def test_run_all_bead_id(self):
        result = cb.run_all()
        self.assertEqual(result["bead_id"], "bd-3hig")

    def test_run_all_section(self):
        result = cb.run_all()
        self.assertEqual(result["section"], "9")

    def test_run_all_has_required_keys(self):
        result = cb.run_all()
        for key in ["bead_id", "section", "title", "total", "passed", "failed", "ok", "checks"]:
            self.assertIn(key, result)

    def test_run_all_total_positive(self):
        result = cb.run_all()
        self.assertGreater(result["total"], 0)

    def test_run_all_counts_consistent(self):
        result = cb.run_all()
        self.assertEqual(result["total"], result["passed"] + result["failed"])

    def test_run_all_checks_list(self):
        result = cb.run_all()
        self.assertIsInstance(result["checks"], list)
        self.assertGreater(len(result["checks"]), 0)

    def test_run_all_check_structure(self):
        result = cb.run_all()
        for check in result["checks"]:
            self.assertIn("check", check)
            self.assertIn("passed", check)
            self.assertIn("detail", check)

    def test_run_all_passes(self):
        result = cb.run_all()
        self.assertTrue(result["ok"], f"run_all failed with {result['failed']} failures")


class TestSelfTest(unittest.TestCase):
    """Test the self_test() function."""

    def test_self_test_returns_true(self):
        result = cb.self_test()
        self.assertTrue(result)

    def test_self_test_no_exception(self):
        try:
            cb.self_test()
        except Exception as e:
            self.fail(f"self_test() raised {type(e).__name__}: {e}")


if __name__ == "__main__":
    unittest.main()
