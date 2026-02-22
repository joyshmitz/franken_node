"""Unit tests for scripts/check_section_10_17_gate.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_section_10_17_gate as mod


class TestConstants(unittest.TestCase):
    def test_section_beads_count(self):
        self.assertEqual(len(mod.SECTION_BEADS), 15)

    def test_bead_ids(self):
        ids = [b[0] for b in mod.SECTION_BEADS]
        for expected in [
            "bd-1nl1", "bd-274s", "bd-1xbc", "bd-3ku8", "bd-gad3",
            "bd-kcg9", "bd-al8i", "bd-26mk", "bd-21fo", "bd-3l2p",
            "bd-2iyk", "bd-nbwo", "bd-2o8b", "bd-383z", "bd-2kd9",
        ]:
            self.assertIn(expected, ids)

    def test_bead_titles_nonempty(self):
        for bead_id, title in mod.SECTION_BEADS:
            self.assertTrue(len(title) > 10, f"{bead_id} title too short")

    def test_bead_id_constant(self):
        self.assertEqual(mod.BEAD, "bd-3t08")

    def test_section_constant(self):
        self.assertEqual(mod.SECTION, "10.17")


class TestEvidencePass(unittest.TestCase):
    def test_verdict_pass(self):
        self.assertTrue(mod._evidence_pass({"verdict": "PASS"}))

    def test_verdict_fail(self):
        self.assertFalse(mod._evidence_pass({"verdict": "FAIL"}))

    def test_overall_pass_true(self):
        self.assertTrue(mod._evidence_pass({"overall_pass": True}))

    def test_overall_pass_false(self):
        self.assertFalse(mod._evidence_pass({"overall_pass": False}))

    def test_status_pass(self):
        self.assertTrue(mod._evidence_pass({"status": "pass"}))

    def test_status_completed(self):
        self.assertTrue(mod._evidence_pass({"status": "completed"}))

    def test_status_completed_with_baseline(self):
        self.assertTrue(mod._evidence_pass({
            "status": "completed_with_baseline_workspace_failures"
        }))

    def test_empty_dict(self):
        self.assertFalse(mod._evidence_pass({}))

    def test_nested_verification_results(self):
        self.assertTrue(mod._evidence_pass({
            "verification_results": {
                "python_checker": {"verdict": "PASS", "passing": 13, "total": 13},
                "python_unit_tests": {"verdict": "PASS", "passed": 4, "total": 4},
                "cargo_check": {"verdict": "FAIL"},
            }
        }))

    def test_nested_verification_results_fail(self):
        self.assertFalse(mod._evidence_pass({
            "verification_results": {
                "python_checker": {"verdict": "FAIL"},
                "python_unit_tests": {"verdict": "PASS"},
            }
        }))


class TestRunAllChecks(unittest.TestCase):
    def test_returns_list(self):
        results = mod.run_all_checks()
        self.assertIsInstance(results, list)

    def test_check_count(self):
        results = mod.run_all_checks()
        # 15 evidence + 15 summary + 2 aggregate + 14 artifacts + 4 gate + 13 domain = 63
        self.assertGreaterEqual(len(results), 60)

    def test_all_checks_have_required_keys(self):
        results = mod.run_all_checks()
        for r in results:
            self.assertIn("check", r)
            self.assertIn("pass", r)
            self.assertIn("detail", r)

    def test_all_checks_pass(self):
        results = mod.run_all_checks()
        failures = [r for r in results if not r["pass"]]
        self.assertEqual(len(failures), 0,
                         "\n".join(f"  FAIL: {r['check']}: {r['detail']}" for r in failures))


class TestRunAll(unittest.TestCase):
    def test_returns_dict(self):
        result = mod.run_all()
        self.assertIsInstance(result, dict)

    def test_bead_id(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-3t08")

    def test_section(self):
        result = mod.run_all()
        self.assertEqual(result["section"], "10.17")

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

    def test_section_beads_list(self):
        result = mod.run_all()
        self.assertEqual(len(result["section_beads"]), 15)
        self.assertIn("bd-1nl1", result["section_beads"])
        self.assertIn("bd-2kd9", result["section_beads"])

    def test_checks_list(self):
        result = mod.run_all()
        self.assertIsInstance(result["checks"], list)
        self.assertGreaterEqual(len(result["checks"]), 60)

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
        self.assertEqual(parsed["bead_id"], "bd-3t08")

    def test_all_required_fields(self):
        result = mod.run_all()
        for key in ["bead_id", "title", "section", "gate", "verdict",
                     "overall_pass", "total", "passed", "failed", "section_beads", "checks"]:
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


class TestDomainCoverage(unittest.TestCase):
    def test_speculation_governance(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "domain_speculation_governance_coverage")
        self.assertTrue(check["pass"])

    def test_adversary_control(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "domain_adversary_control_coverage")
        self.assertTrue(check["pass"])

    def test_capability_enforcement(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "domain_capability_enforcement_coverage")
        self.assertTrue(check["pass"])

    def test_security_firewall(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "domain_security_firewall_coverage")
        self.assertTrue(check["pass"])


class TestGateDeliverables(unittest.TestCase):
    def test_gate_evidence(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "gate_evidence")
        self.assertTrue(check["pass"])

    def test_gate_summary(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "gate_summary")
        self.assertTrue(check["pass"])

    def test_gate_spec(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "gate_spec")
        self.assertTrue(check["pass"])

    def test_gate_tests(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "gate_tests")
        self.assertTrue(check["pass"])


if __name__ == "__main__":
    unittest.main()
