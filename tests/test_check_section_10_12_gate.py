"""Unit tests for scripts/check_section_10_12_gate.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_section_10_12_gate as mod


class TestConstants(unittest.TestCase):
    def test_section_beads_count(self):
        self.assertEqual(len(mod.SECTION_BEADS), 7)

    def test_bead_ids(self):
        ids = [b[0] for b in mod.SECTION_BEADS]
        for expected in ["bd-3hm", "bd-3j4", "bd-5si", "bd-3c2", "bd-y0v", "bd-2aj", "bd-n1w"]:
            self.assertIn(expected, ids)

    def test_frontier_programs_count(self):
        self.assertEqual(len(mod.FRONTIER_PROGRAMS), 5)

    def test_bead_id_constant(self):
        self.assertEqual(mod.BEAD, "bd-1d6x")

    def test_section_constant(self):
        self.assertEqual(mod.SECTION, "10.12")


class TestEvidencePass(unittest.TestCase):
    def test_verdict_pass(self):
        self.assertTrue(mod._evidence_pass({"verdict": "PASS"}))

    def test_overall_pass_true(self):
        self.assertTrue(mod._evidence_pass({"overall_pass": True}))

    def test_status_pass(self):
        self.assertTrue(mod._evidence_pass({"status": "pass"}))

    def test_nested_verification_results(self):
        self.assertTrue(mod._evidence_pass({
            "verification_results": {
                "python_checker": {"verdict": "PASS"},
                "python_unit_tests": {"verdict": "PASS"},
            }
        }))

    def test_fail_case(self):
        self.assertFalse(mod._evidence_pass({"verdict": "FAIL"}))


class TestRunAllChecks(unittest.TestCase):
    def test_returns_list(self):
        results = mod.run_all_checks()
        self.assertIsInstance(results, list)

    def test_check_count(self):
        results = mod.run_all_checks()
        self.assertGreaterEqual(len(results), 40)

    def test_all_checks_have_required_keys(self):
        results = mod.run_all_checks()
        for result in results:
            self.assertIn("check", result)
            self.assertIn("pass", result)
            self.assertIn("detail", result)

    def test_all_checks_pass(self):
        results = mod.run_all_checks()
        failures = [r for r in results if not r["pass"]]
        self.assertEqual(
            len(failures),
            0,
            "\n".join(f"  FAIL: {r['check']}: {r['detail']}" for r in failures),
        )


class TestRunAll(unittest.TestCase):
    def test_returns_dict(self):
        result = mod.run_all()
        self.assertIsInstance(result, dict)

    def test_bead_id(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-1d6x")

    def test_section(self):
        result = mod.run_all()
        self.assertEqual(result["section"], "10.12")

    def test_gate_flag(self):
        result = mod.run_all()
        self.assertTrue(result["gate"])

    def test_verdict_pass(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def test_overall_pass(self):
        result = mod.run_all()
        self.assertTrue(result["overall_pass"])

    def test_zero_failed(self):
        result = mod.run_all()
        self.assertEqual(result["failed"], 0, self._failing(result))

    def test_events_complete(self):
        result = mod.run_all()
        self.assertTrue(result["events_complete"])
        self.assertEqual(result["missing_events"], [])

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["pass"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        self.assertTrue(mod.self_test())


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        result = mod.run_all()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-1d6x")

    def test_all_required_fields(self):
        result = mod.run_all()
        for key in [
            "bead_id",
            "title",
            "section",
            "gate",
            "verdict",
            "overall_pass",
            "total",
            "passed",
            "failed",
            "section_beads",
            "frontier_programs",
            "events",
            "events_complete",
            "checks",
        ]:
            self.assertIn(key, result)


class TestIdempotent(unittest.TestCase):
    def test_results_cleared(self):
        mod.run_all_checks()
        first_len = len(mod.RESULTS)
        mod.run_all_checks()
        second_len = len(mod.RESULTS)
        self.assertEqual(first_len, second_len)


class TestPerBeadChecks(unittest.TestCase):
    def test_all_evidence_present(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "all_evidence_present")
        self.assertTrue(check["pass"])

    def test_all_verdicts_pass(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "all_verdicts_pass")
        self.assertTrue(check["pass"])

    def test_each_evidence_passes(self):
        results = mod.run_all_checks()
        for bead_id, _ in mod.SECTION_BEADS:
            check = next(r for r in results if r["check"] == f"evidence_{bead_id}")
            self.assertTrue(check["pass"], f"{bead_id} evidence not PASS")

    def test_each_summary_exists(self):
        results = mod.run_all_checks()
        for bead_id, _ in mod.SECTION_BEADS:
            check = next(r for r in results if r["check"] == f"summary_{bead_id}")
            self.assertTrue(check["pass"], f"{bead_id} summary missing")


class TestReproducibilityAudit(unittest.TestCase):
    def test_manifest_checks(self):
        results = mod.run_all_checks()
        for name in [
            "repro_manifest_exists",
            "repro_manifest_parseable",
            "repro_manifest_schema",
            "repro_required_programs",
            "repro_program_gate_status_pass",
            "repro_program_fingerprints",
            "repro_manifest_metadata",
            "repro_manifest_timing_coverage",
            "repro_n1w_invariant",
            "repro_n1w_summary_external",
        ]:
            check = next(r for r in results if r["check"] == name)
            self.assertTrue(check["pass"], f"{name} failed: {check['detail']}")


class TestDegradedModeCoverage(unittest.TestCase):
    def test_all_capabilities(self):
        results = mod.run_all_checks()
        for capability in mod.DEGRADED_MODE_SIGNAL_RULES:
            check = next(r for r in results if r["check"] == f"degraded_contract_{capability}")
            self.assertTrue(check["pass"], f"{capability} degraded/fallback contract missing")

    def test_aggregate_coverage(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "degraded_contracts_all_capabilities")
        self.assertTrue(check["pass"])


class TestStructuredLogging(unittest.TestCase):
    def test_event_names_present(self):
        result = mod.run_all()
        events = {entry["event"] for entry in result["events"]}
        for expected in mod.REQUIRED_GATE_EVENTS:
            self.assertIn(expected, events)

    def test_phase_event_check(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "structured_logging_phase_events")
        self.assertTrue(check["pass"])


class TestGateDeliverables(unittest.TestCase):
    def test_gate_script(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "gate_script")
        self.assertTrue(check["pass"])

    def test_gate_tests(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "gate_tests")
        self.assertTrue(check["pass"])

    def test_gate_spec(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "gate_spec")
        self.assertTrue(check["pass"])


if __name__ == "__main__":
    unittest.main()
