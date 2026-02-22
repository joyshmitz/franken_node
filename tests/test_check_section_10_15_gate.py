"""Unit tests for scripts/check_section_10_15_gate.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_section_10_15_gate as mod


class TestConstants(unittest.TestCase):
    def test_section_beads_count(self):
        self.assertEqual(len(mod.SECTION_BEADS), 25)

    def test_bead_ids(self):
        ids = [b[0] for b in mod.SECTION_BEADS]
        for expected in [
            "bd-1id0", "bd-2177", "bd-2g6r", "bd-721z", "bd-2tdi",
            "bd-1cs7", "bd-1n5p", "bd-cuut", "bd-3014", "bd-1cwp",
            "bd-3h63", "bd-181w", "bd-1hbw", "bd-15j6", "bd-tyr2",
            "bd-145n", "bd-3tpg", "bd-3u6o", "bd-25oa", "bd-h93z",
            "bd-3gnh", "bd-1f8m", "bd-1xwz", "bd-33kj", "bd-2h2s",
        ]:
            self.assertIn(expected, ids)

    def test_bead_titles_nonempty(self):
        for bead_id, title in mod.SECTION_BEADS:
            self.assertTrue(len(title) > 10, f"{bead_id} title too short")

    def test_bead_id_constant(self):
        self.assertEqual(mod.BEAD, "bd-20eg")

    def test_section_constant(self):
        self.assertEqual(mod.SECTION, "10.15")


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

    def test_status_pass_uppercase(self):
        self.assertTrue(mod._evidence_pass({"status": "Pass"}))

    def test_empty_dict(self):
        self.assertFalse(mod._evidence_pass({}))

    def test_completed_with_baseline_failures(self):
        self.assertTrue(mod._evidence_pass({
            "status": "completed_with_baseline_workspace_failures"
        }))

    def test_partial_blocked_with_deliverables(self):
        self.assertTrue(mod._evidence_pass({
            "overall_status": "partial_blocked_by_preexisting_workspace_failures",
            "deliverables": [
                {"path": "a.rs", "exists": True},
                {"path": "b.rs", "exists": True},
            ],
        }))

    def test_partial_blocked_without_deliverables(self):
        self.assertFalse(mod._evidence_pass({
            "overall_status": "partial_blocked_by_preexisting_workspace_failures",
        }))


class TestRunAllChecks(unittest.TestCase):
    def test_returns_list(self):
        results = mod.run_all_checks()
        self.assertIsInstance(results, list)

    def test_check_count(self):
        results = mod.run_all_checks()
        self.assertGreaterEqual(len(results), 80)

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
        self.assertEqual(result["bead_id"], "bd-20eg")

    def test_section(self):
        result = mod.run_all()
        self.assertEqual(result["section"], "10.15")

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
        self.assertEqual(len(result["section_beads"]), 25)
        self.assertIn("bd-1id0", result["section_beads"])
        self.assertIn("bd-721z", result["section_beads"])

    def test_checks_list(self):
        result = mod.run_all()
        self.assertIsInstance(result["checks"], list)
        self.assertGreaterEqual(len(result["checks"]), 80)

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
        self.assertEqual(parsed["bead_id"], "bd-20eg")

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

    def test_each_spec_exists(self):
        results = mod.run_all_checks()
        for bead_id, _ in mod.SECTION_BEADS:
            check = next(r for r in results if r["check"] == f"spec_{bead_id}")
            self.assertTrue(check["pass"], f"{bead_id} spec contract missing")


class TestKeyModules(unittest.TestCase):
    def test_region_ownership(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "module_region_ownership")
        self.assertTrue(check["pass"])

    def test_cancellation_protocol(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "module_cancellation_protocol")
        self.assertTrue(check["pass"])

    def test_obligation_tracker(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "module_obligation_tracker")
        self.assertTrue(check["pass"])

    def test_ambient_authority_gate(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "module_ambient_authority_gate")
        self.assertTrue(check["pass"])


class TestKeySpecs(unittest.TestCase):
    def test_tri_kernel_ownership(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "spec_tri_kernel_ownership")
        self.assertTrue(check["pass"])

    def test_region_tree_topology(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "spec_region_tree_topology")
        self.assertTrue(check["pass"])

    def test_ambient_authority_policy(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "spec_ambient_authority_policy")
        self.assertTrue(check["pass"])

    def test_ambient_authority_allowlist(self):
        results = mod.run_all_checks()
        check = next(r for r in results if r["check"] == "spec_ambient_authority_allowlist")
        self.assertTrue(check["pass"])


if __name__ == "__main__":
    unittest.main()
