"""Unit tests for scripts/check_control_transport_faults.py (bd-3u6o).

Validates the verification gate script for the canonical virtual transport
fault harness enforcement on distributed control protocols.
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_control_transport_faults as mod


class TestConstants(unittest.TestCase):
    """Verify the check script defines the expected constants."""

    def test_protocols_count(self):
        self.assertEqual(len(mod.PROTOCOLS), 4)

    def test_protocols_list(self):
        expected = {
            "remote_fencing",
            "cross_node_rollout",
            "epoch_barrier_participation",
            "distributed_saga_steps",
        }
        self.assertEqual(set(mod.PROTOCOLS), expected)

    def test_fault_classes_count(self):
        self.assertEqual(len(mod.FAULT_CLASSES), 4)

    def test_fault_classes_list(self):
        expected = {"DROP", "REORDER", "CORRUPT", "PARTITION"}
        self.assertEqual(set(mod.FAULT_CLASSES), expected)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_invariants_list(self):
        expected = {
            "INV-VTF-DETERMINISTIC",
            "INV-VTF-CORRECT-OR-FAIL",
            "INV-VTF-NO-CUSTOM",
            "INV-VTF-SEED-STABLE",
        }
        self.assertEqual(set(mod.INVARIANTS), expected)


class TestPaths(unittest.TestCase):
    """Verify the check script defines valid file paths."""

    def test_doc_path(self):
        self.assertTrue(mod.DOC.is_file(), f"doc not found: {mod.DOC}")

    def test_report_path(self):
        self.assertTrue(mod.REPORT.is_file(), f"report not found: {mod.REPORT}")

    def test_spec_path(self):
        self.assertTrue(mod.SPEC.is_file(), f"spec not found: {mod.SPEC}")

    def test_upstream_harness_path(self):
        self.assertTrue(
            mod.UPSTREAM_HARNESS.is_file(),
            f"upstream harness not found: {mod.UPSTREAM_HARNESS}",
        )


class TestCheckDocExists(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_doc_exists()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckReportExists(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_report_exists()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckReportValid(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_report_valid()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckReportProtocols(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_report_protocols()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckReportFaultClasses(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_report_fault_classes()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckReportSummary(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_report_summary()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckDocProtocols(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_doc_protocols()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckDocFaultClasses(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_doc_fault_classes()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckDocInvariants(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_doc_invariants()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckDocSeedModel(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_doc_seed_model()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckUpstreamHarnessExists(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_upstream_harness_exists()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckSpecExists(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_spec_exists()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckSpecBeadId(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_spec_bead_id()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckSpecSection(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_spec_section()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckSpecInvariants(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_spec_invariants()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckSpecAcceptanceCriteria(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_spec_acceptance_criteria()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckUnitTestsExist(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_unit_tests_exist()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckVerificationEvidence(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_verification_evidence()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckVerificationSummary(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_verification_summary()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestCheckDocExpectedBehaviors(unittest.TestCase):
    def test_passes(self):
        mod.RESULTS.clear()
        mod.check_doc_expected_behaviors()
        self.assertTrue(mod.RESULTS[-1]["pass"])


class TestRunAll(unittest.TestCase):
    def test_overall_verdict_pass(self):
        report = mod.run_all()
        failing = [c for c in report["checks"] if not c["pass"]]
        msg = "\n".join(
            f"  FAIL: {c['id']} {c['check']}: {c['details']['message']}"
            for c in failing
        )
        self.assertEqual(report["verdict"], "PASS", f"Failures:\n{msg}")

    def test_total_checks_at_least_20(self):
        report = mod.run_all()
        self.assertGreaterEqual(report["total"], 20)

    def test_zero_failures(self):
        report = mod.run_all()
        self.assertEqual(report["failed"], 0)

    def test_bead_id(self):
        report = mod.run_all()
        self.assertEqual(report["bead_id"], "bd-3u6o")

    def test_section(self):
        report = mod.run_all()
        self.assertEqual(report["section"], "10.15")


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok = mod.self_test()
        self.assertTrue(ok)


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        report = mod.run_all()
        parsed = json.loads(json.dumps(report))
        self.assertEqual(parsed["bead_id"], "bd-3u6o")

    def test_all_required_fields(self):
        report = mod.run_all()
        for key in ["bead_id", "title", "section", "verdict", "total", "passed", "failed", "checks"]:
            self.assertIn(key, report)

    def test_check_structure(self):
        report = mod.run_all()
        for check in report["checks"]:
            self.assertIn("id", check)
            self.assertIn("check", check)
            self.assertIn("status", check)
            self.assertIn("pass", check)
            self.assertIn("details", check)


class TestAllCheckFunctions(unittest.TestCase):
    """Verify ALL_CHECKS contains the expected number of check functions."""

    def test_check_count(self):
        self.assertEqual(len(mod.ALL_CHECKS), 20)


if __name__ == "__main__":
    unittest.main()
