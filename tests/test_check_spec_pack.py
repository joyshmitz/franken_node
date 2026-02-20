#!/usr/bin/env python3
"""Unit tests for check_spec_pack.py."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_spec_pack as csp


class TestCheckDocsExist(unittest.TestCase):
    def test_all_docs_exist(self):
        result = csp.check_docs_exist()
        self.assertEqual(result["id"], "PACK-EXISTS")
        self.assertEqual(result["status"], "PASS")
        for doc in csp.REQUIRED_DOCS:
            self.assertTrue(result["details"]["documents"][doc])

    def test_missing_doc_fails(self):
        orig = csp.REQUIRED_DOCS[:]
        csp.REQUIRED_DOCS.append("NONEXISTENT.md")
        try:
            result = csp.check_docs_exist()
            self.assertEqual(result["status"], "FAIL")
            self.assertFalse(result["details"]["documents"]["NONEXISTENT.md"])
        finally:
            csp.REQUIRED_DOCS.pop()


class TestCheckADRReferences(unittest.TestCase):
    def test_all_docs_reference_adr(self):
        result = csp.check_adr_references()
        self.assertEqual(result["id"], "PACK-ADR-REF")
        self.assertEqual(result["status"], "PASS")
        for doc in csp.REQUIRED_DOCS:
            self.assertTrue(result["details"]["references"][doc])


class TestCheckNotBlueprintWarning(unittest.TestCase):
    def test_warning_present(self):
        result = csp.check_not_blueprint_warning()
        self.assertEqual(result["id"], "PACK-NOT-BLUEPRINT")
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["details"]["warning_present"])

    def test_missing_file_fails(self):
        with patch.object(csp, "PACK_DIR", Path("/nonexistent")):
            result = csp.check_not_blueprint_warning()
            self.assertEqual(result["status"], "FAIL")


class TestCheckFeatureParityContent(unittest.TestCase):
    def test_content_present(self):
        result = csp.check_feature_parity_content()
        self.assertEqual(result["id"], "PACK-PARITY")
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["details"]["has_family_tracking"])
        self.assertTrue(result["details"]["has_band_tracking"])
        self.assertTrue(result["details"]["has_status_tracking"])

    def test_missing_file_fails(self):
        with patch.object(csp, "PACK_DIR", Path("/nonexistent")):
            result = csp.check_feature_parity_content()
            self.assertEqual(result["status"], "FAIL")


class TestCheckReleaseGate(unittest.TestCase):
    def test_release_gate_present(self):
        result = csp.check_release_gate()
        self.assertEqual(result["id"], "PACK-GATE")
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["details"]["release_gated"])

    def test_missing_file_fails(self):
        with patch.object(csp, "PACK_DIR", Path("/nonexistent")):
            result = csp.check_release_gate()
            self.assertEqual(result["status"], "FAIL")


class TestPackDir(unittest.TestCase):
    def test_pack_dir_exists(self):
        self.assertTrue(csp.PACK_DIR.is_dir())

    def test_required_docs_list_has_four(self):
        self.assertEqual(len(csp.REQUIRED_DOCS), 4)


if __name__ == "__main__":
    unittest.main()
