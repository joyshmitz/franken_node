#!/usr/bin/env python3
"""Unit tests for check_fixture_corpus.py."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_fixture_corpus as cfc


class TestLoadFixtures(unittest.TestCase):
    def test_loads_nonzero_fixtures(self):
        fixtures = cfc.load_fixtures()
        self.assertGreater(len(fixtures), 0)

    def test_all_have_id(self):
        for fx in cfc.load_fixtures():
            self.assertIn("id", fx)

    def test_no_duplicate_ids(self):
        ids = [fx["id"] for fx in cfc.load_fixtures()]
        self.assertEqual(len(ids), len(set(ids)))


class TestCorpusStructure(unittest.TestCase):
    def test_structure_passes(self):
        result = cfc.check_corpus_structure()
        self.assertEqual(result["status"], "PASS")
        for band in ["core", "high-value", "edge"]:
            self.assertTrue(result["details"]["dirs"][band])


class TestCapturePrograms(unittest.TestCase):
    def test_captures_exist(self):
        result = cfc.check_capture_programs()
        self.assertEqual(result["status"], "PASS")
        self.assertGreaterEqual(result["details"]["count"], 2)

    def test_missing_dir_fails(self):
        with patch.object(cfc, "CAPTURE_DIR", Path("/nonexistent")):
            result = cfc.check_capture_programs()
            self.assertEqual(result["status"], "FAIL")


class TestFixtureValidity(unittest.TestCase):
    def test_all_valid(self):
        fixtures = cfc.load_fixtures()
        result = cfc.check_fixture_validity(fixtures)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["details"]["valid"], result["details"]["total"])

    def test_missing_fields_fails(self):
        bad = [{"id": "fixture:x:y:z"}]
        result = cfc.check_fixture_validity(bad)
        self.assertEqual(result["status"], "FAIL")

    def test_bad_id_fails(self):
        bad = [{"id": "bad-id", "api_family": "x", "api_name": "y",
                "band": "core", "input": {}, "expected_output": {}}]
        result = cfc.check_fixture_validity(bad)
        self.assertEqual(result["status"], "FAIL")

    def test_bad_band_fails(self):
        bad = [{"id": "fixture:x:y:z", "api_family": "x", "api_name": "y",
                "band": "invalid", "input": {}, "expected_output": {}}]
        result = cfc.check_fixture_validity(bad)
        self.assertEqual(result["status"], "FAIL")


class TestFixtureUniqueness(unittest.TestCase):
    def test_unique_passes(self):
        fixtures = cfc.load_fixtures()
        result = cfc.check_fixture_uniqueness(fixtures)
        self.assertEqual(result["status"], "PASS")

    def test_duplicate_fails(self):
        dupes = [{"id": "fixture:x:y:z"}, {"id": "fixture:x:y:z"}]
        result = cfc.check_fixture_uniqueness(dupes)
        self.assertEqual(result["status"], "FAIL")


class TestBandCoverage(unittest.TestCase):
    def test_coverage_passes(self):
        fixtures = cfc.load_fixtures()
        result = cfc.check_band_coverage(fixtures)
        self.assertEqual(result["status"], "PASS")
        self.assertGreaterEqual(len(result["details"]["families_by_band"].get("core", [])), 3)

    def test_insufficient_core_fails(self):
        fixtures = [{"band": "core", "api_family": "fs", "api_name": "readFile"}]
        result = cfc.check_band_coverage(fixtures)
        self.assertEqual(result["status"], "FAIL")


class TestRegistryAlignment(unittest.TestCase):
    def test_alignment_passes(self):
        fixtures = cfc.load_fixtures()
        result = cfc.check_registry_alignment(fixtures)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(len(result["details"]["missing"]), 0)


if __name__ == "__main__":
    unittest.main()
