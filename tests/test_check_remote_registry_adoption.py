#!/usr/bin/env python3
"""Unit tests for check_remote_registry_adoption.py."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_remote_registry_adoption as cra


class TestConstants(unittest.TestCase):
    def test_five_required_computation_names(self):
        self.assertEqual(len(cra.REQUIRED_COMPUTATION_NAMES), 5)

    def test_computation_names_follow_canonical_format(self):
        """All names must match domain.action.vN pattern."""
        for name in cra.REQUIRED_COMPUTATION_NAMES:
            parts = name.split(".")
            self.assertEqual(len(parts), 3, f"Name {name} must have 3 dot-separated parts")
            self.assertTrue(parts[2].startswith("v"), f"Version part of {name} must start with 'v'")
            self.assertTrue(parts[2][1:].isdigit(), f"Version part of {name} must end with digits")

    def test_divergent_patterns_defined(self):
        self.assertGreater(len(cra.DIVERGENT_PATTERNS), 0)

    def test_connector_health_probe_in_names(self):
        self.assertIn("connector.health_probe.v1", cra.REQUIRED_COMPUTATION_NAMES)

    def test_federation_sync_delta_in_names(self):
        self.assertIn("federation.sync_delta.v1", cra.REQUIRED_COMPUTATION_NAMES)


class TestCheckRegistrySourceExists(unittest.TestCase):
    def test_passes(self):
        result = cra.check_registry_source_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CRA-SRC")


class TestCheckAdoptionDocExists(unittest.TestCase):
    def test_passes(self):
        result = cra.check_adoption_doc_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CRA-DOC")


class TestCheckAdoptionReportExists(unittest.TestCase):
    def test_passes(self):
        result = cra.check_adoption_report_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CRA-REPORT")

    def test_report_has_bead_field(self):
        data = json.loads(cra.ADOPTION_REPORT.read_text())
        self.assertEqual(data["bead"], "bd-3014")

    def test_report_has_section_field(self):
        data = json.loads(cra.ADOPTION_REPORT.read_text())
        self.assertEqual(data["section"], "10.15")

    def test_report_has_adoption_status(self):
        data = json.loads(cra.ADOPTION_REPORT.read_text())
        self.assertEqual(data["adoption_status"], "documented")


class TestCheckComputationNamesDocumented(unittest.TestCase):
    def test_passes(self):
        result = cra.check_computation_names_documented()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CRA-NAMES")

    def test_no_missing_names(self):
        result = cra.check_computation_names_documented()
        self.assertEqual(result["details"]["missing"], [])


class TestCheckErrorCodeInRegistry(unittest.TestCase):
    def test_passes(self):
        result = cra.check_error_code_in_registry()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CRA-ERRCODE")


class TestCheckValidateMethodExists(unittest.TestCase):
    def test_passes(self):
        result = cra.check_validate_method_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CRA-VALIDATE")


class TestCheckNoDivergentRegistries(unittest.TestCase):
    def test_passes(self):
        result = cra.check_no_divergent_registries()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CRA-DIVERGENT")

    def test_no_violations(self):
        result = cra.check_no_divergent_registries()
        self.assertEqual(result["details"]["violations"], [])


class TestCheckSpecContractExists(unittest.TestCase):
    def test_passes(self):
        result = cra.check_spec_contract_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CRA-SPEC")


class TestCheckTestFileExists(unittest.TestCase):
    def test_passes(self):
        result = cra.check_test_file_exists()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CRA-TESTS")


class TestCheckAdoptionDocContent(unittest.TestCase):
    def test_passes(self):
        result = cra.check_adoption_doc_content()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CRA-CONTENT")

    def test_no_missing_sections(self):
        result = cra.check_adoption_doc_content()
        self.assertEqual(result["details"]["missing_sections"], [])


class TestCheckReportComputationCount(unittest.TestCase):
    def test_passes(self):
        result = cra.check_report_computation_count()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CRA-COUNT")

    def test_five_computations(self):
        result = cra.check_report_computation_count()
        self.assertEqual(result["details"]["count"], 5)


class TestCheckCanonicalNamingFunction(unittest.TestCase):
    def test_passes(self):
        result = cra.check_canonical_naming_function()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["id"], "CRA-NAMING")


class TestSelfTest(unittest.TestCase):
    def test_verdict_pass(self):
        result = cra.self_test()
        self.assertEqual(result["verdict"], "PASS")

    def test_all_checks_present(self):
        result = cra.self_test()
        self.assertGreaterEqual(result["summary"]["total_checks"], 12)

    def test_no_failures(self):
        result = cra.self_test()
        self.assertEqual(result["summary"]["failing_checks"], 0)

    def test_bead_field(self):
        result = cra.self_test()
        self.assertEqual(result["bead"], "bd-3014")

    def test_section_field(self):
        result = cra.self_test()
        self.assertEqual(result["section"], "10.15")

    def test_gate_name(self):
        result = cra.self_test()
        self.assertEqual(result["gate"], "remote_registry_adoption_verification")


if __name__ == "__main__":
    unittest.main()
