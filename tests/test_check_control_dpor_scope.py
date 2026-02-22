"""Unit tests for scripts/check_control_dpor_scope.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_control_dpor_scope as mod


class TestConstants(unittest.TestCase):
    def test_required_classes_count(self):
        self.assertEqual(len(mod.REQUIRED_CLASSES), 4)

    def test_required_invariants_count(self):
        self.assertEqual(len(mod.REQUIRED_INVARIANTS), 4)

    def test_required_upstream_types_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_UPSTREAM_TYPES), 8)

    def test_required_doc_sections_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_DOC_SECTIONS), 5)

    def test_required_report_keys_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_REPORT_KEYS), 7)

    def test_budget_keywords_count(self):
        self.assertGreaterEqual(len(mod.BUDGET_KEYWORDS), 5)

    def test_counterexample_keywords_count(self):
        self.assertGreaterEqual(len(mod.COUNTEREXAMPLE_KEYWORDS), 5)


class TestRequiredClassNames(unittest.TestCase):
    def test_epoch_transition_lease_renewal(self):
        self.assertIn("epoch_transition_lease_renewal", mod.REQUIRED_CLASSES)

    def test_remote_computation_evidence_emission(self):
        self.assertIn("remote_computation_evidence_emission", mod.REQUIRED_CLASSES)

    def test_cancellation_saga_compensation(self):
        self.assertIn("cancellation_saga_compensation", mod.REQUIRED_CLASSES)

    def test_epoch_barrier_fencing_token(self):
        self.assertIn("epoch_barrier_fencing_token", mod.REQUIRED_CLASSES)


class TestRequiredInvariantNames(unittest.TestCase):
    def test_bounded(self):
        self.assertIn("INV-DPOR-BOUNDED", mod.REQUIRED_INVARIANTS)

    def test_invariant_check(self):
        self.assertIn("INV-DPOR-INVARIANT-CHECK", mod.REQUIRED_INVARIANTS)

    def test_counterexample(self):
        self.assertIn("INV-DPOR-COUNTEREXAMPLE", mod.REQUIRED_INVARIANTS)

    def test_canonical(self):
        self.assertIn("INV-DPOR-CANONICAL", mod.REQUIRED_INVARIANTS)


class TestCheckScopeDocExists(unittest.TestCase):
    def test_scope_doc_passes(self):
        result = mod.check_scope_doc_exists()
        self.assertEqual(result["status"], "PASS", result["details"])
        self.assertEqual(result["id"], "CDP-001")

    def test_scope_doc_has_details(self):
        result = mod.check_scope_doc_exists()
        self.assertIn("file", result["details"])
        self.assertIn("found", result["details"])


class TestCheckReportExistsAndValid(unittest.TestCase):
    def test_report_passes(self):
        result = mod.check_report_exists_and_valid()
        self.assertEqual(result["status"], "PASS", result["details"])
        self.assertEqual(result["id"], "CDP-002")


class TestCheckInteractionClasses(unittest.TestCase):
    def test_all_classes_pass(self):
        results = mod.check_interaction_classes_documented()
        for r in results:
            self.assertEqual(r["status"], "PASS", f"FAIL: {r['details']}")

    def test_at_least_8_checks(self):
        results = mod.check_interaction_classes_documented()
        self.assertGreaterEqual(len(results), 8)

    def test_all_are_cdp_003(self):
        results = mod.check_interaction_classes_documented()
        for r in results:
            self.assertEqual(r["id"], "CDP-003")


class TestCheckUpstreamExplorer(unittest.TestCase):
    def test_all_upstream_pass(self):
        results = mod.check_upstream_explorer()
        for r in results:
            self.assertEqual(r["status"], "PASS", f"FAIL: {r['details']}")

    def test_upstream_file_check(self):
        results = mod.check_upstream_explorer()
        file_check = results[0]
        self.assertEqual(file_check["id"], "CDP-004")
        self.assertTrue(file_check["details"]["found"])

    def test_upstream_types_count(self):
        results = mod.check_upstream_explorer()
        # 1 file check + N type checks
        self.assertGreaterEqual(len(results), 9)


class TestCheckBudgetDefined(unittest.TestCase):
    def test_all_budget_pass(self):
        results = mod.check_budget_defined()
        for r in results:
            self.assertEqual(r["status"], "PASS", f"FAIL: {r['details']}")

    def test_budget_count(self):
        results = mod.check_budget_defined()
        self.assertGreaterEqual(len(results), 6)


class TestCheckInvariantsDocumented(unittest.TestCase):
    def test_all_invariants_pass(self):
        results = mod.check_invariants_documented()
        for r in results:
            self.assertEqual(r["status"], "PASS", f"FAIL: {r['details']}")

    def test_invariant_check_count(self):
        results = mod.check_invariants_documented()
        # 4 invariants x 3 locations (doc, spec, report) = 12
        self.assertGreaterEqual(len(results), 12)


class TestCheckCounterexampleFormat(unittest.TestCase):
    def test_all_counterexample_pass(self):
        results = mod.check_counterexample_format()
        for r in results:
            self.assertEqual(r["status"], "PASS", f"FAIL: {r['details']}")

    def test_counterexample_count(self):
        results = mod.check_counterexample_format()
        self.assertGreaterEqual(len(results), 7)


class TestCheckDocSections(unittest.TestCase):
    def test_all_sections_pass(self):
        results = mod.check_doc_sections()
        for r in results:
            self.assertEqual(r["status"], "PASS", f"FAIL: {r['details']}")


class TestCheckSpecExists(unittest.TestCase):
    def test_spec_passes(self):
        result = mod.check_spec_exists()
        self.assertEqual(result["status"], "PASS", result["details"])


class TestCheckTestFileExists(unittest.TestCase):
    def test_test_file_passes(self):
        result = mod.check_test_file_exists()
        self.assertEqual(result["status"], "PASS", result["details"])


class TestCheckReportSummaryTotals(unittest.TestCase):
    def test_all_totals_pass(self):
        results = mod.check_report_summary_totals()
        for r in results:
            self.assertEqual(r["status"], "PASS", f"FAIL: {r['details']}")

    def test_totals_count(self):
        results = mod.check_report_summary_totals()
        self.assertGreaterEqual(len(results), 4)


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"], self._failing(result))

    def test_verdict_pass(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-25oa")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.15")

    def test_zero_failing(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0, self._failing(result))

    def test_many_checks(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["summary"]["total"], 40)

    def test_has_title(self):
        result = mod.run_checks()
        self.assertIn("DPOR", result["title"])

    def _failing(self, result):
        failures = [c for c in result["checks"] if c["status"] == "FAIL"]
        return "\n".join(
            f"  FAIL: {c['id']}: {json.dumps(c['details'])}" for c in failures[:10]
        )


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        ok, msg = mod.self_test()
        self.assertTrue(ok, msg)


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        result = mod.run_checks()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-25oa")

    def test_all_fields(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "overall_pass", "verdict", "summary", "checks"]:
            self.assertIn(key, result)

    def test_check_structure(self):
        result = mod.run_checks()
        for c in result["checks"]:
            self.assertIn("id", c)
            self.assertIn("status", c)
            self.assertIn("details", c)
            self.assertIn(c["status"], ("PASS", "FAIL"))


class TestCheckRustTestFile(unittest.TestCase):
    def test_all_rust_checks_pass(self):
        results = mod.check_rust_test_file()
        for r in results:
            self.assertEqual(r["status"], "PASS", f"FAIL: {r['details']}")

    def test_rust_check_count(self):
        results = mod.check_rust_test_file()
        # 1 file exists + 12 markers + 1 test count + 4 classes = 18
        self.assertGreaterEqual(len(results), 18)

    def test_all_are_dpr_001(self):
        results = mod.check_rust_test_file()
        for r in results:
            self.assertEqual(r["id"], "DPR-001")


class TestCheckDprEventCodes(unittest.TestCase):
    def test_all_event_codes_pass(self):
        results = mod.check_dpr_event_codes()
        for r in results:
            self.assertEqual(r["status"], "PASS", f"FAIL: {r['details']}")

    def test_event_code_count(self):
        results = mod.check_dpr_event_codes()
        # 5 codes x 2 locations (scope_doc, spec_contract) = 10
        self.assertGreaterEqual(len(results), 10)

    def test_all_are_dpr_002(self):
        results = mod.check_dpr_event_codes()
        for r in results:
            self.assertEqual(r["id"], "DPR-002")


class TestCheckResultsReport(unittest.TestCase):
    def test_all_results_pass(self):
        results = mod.check_results_report()
        for r in results:
            self.assertEqual(r["status"], "PASS", f"FAIL: {r['details']}")

    def test_results_report_count(self):
        results = mod.check_results_report()
        # 1 exists + 1 bead_id + 1 verdict + 1 classes count + 4 class passed + 5 event codes = 13
        self.assertGreaterEqual(len(results), 13)

    def test_all_are_dpr_003(self):
        results = mod.check_results_report()
        for r in results:
            self.assertEqual(r["id"], "DPR-003")


class TestCheckEvidenceArtifacts(unittest.TestCase):
    def test_all_evidence_pass(self):
        results = mod.check_evidence_artifacts()
        for r in results:
            self.assertEqual(r["status"], "PASS", f"FAIL: {r['details']}")

    def test_evidence_count(self):
        results = mod.check_evidence_artifacts()
        self.assertEqual(len(results), 2)

    def test_all_are_dpr_004(self):
        results = mod.check_evidence_artifacts()
        for r in results:
            self.assertEqual(r["id"], "DPR-004")


class TestDprEventCodeConstants(unittest.TestCase):
    def test_five_dpr_codes(self):
        self.assertEqual(len(mod.REQUIRED_DPR_EVENT_CODES), 5)

    def test_dpr_001(self):
        self.assertIn("DPR-001", mod.REQUIRED_DPR_EVENT_CODES)

    def test_dpr_005(self):
        self.assertIn("DPR-005", mod.REQUIRED_DPR_EVENT_CODES)


class TestRustTestMarkers(unittest.TestCase):
    def test_markers_count(self):
        self.assertGreaterEqual(len(mod.RUST_TEST_MARKERS), 12)

    def test_interaction_class_markers(self):
        for cls in mod.REQUIRED_CLASSES:
            self.assertIn(cls, mod.RUST_TEST_MARKERS)


class TestResultHelper(unittest.TestCase):
    def test_result_structure(self):
        r = mod._result("CDP-999", "PASS", {"key": "val"})
        self.assertEqual(r["id"], "CDP-999")
        self.assertEqual(r["status"], "PASS")
        self.assertEqual(r["details"]["key"], "val")

    def test_result_fail(self):
        r = mod._result("CDP-999", "FAIL", {"missing": True})
        self.assertEqual(r["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
