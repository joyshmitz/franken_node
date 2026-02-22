"""Unit tests for scripts/check_section_10_10_gate.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_section_10_10_gate as mod


class TestConstants(unittest.TestCase):
    def test_section_bead_count(self):
        self.assertEqual(len(mod.SECTION_BEADS), 11)

    def test_expected_beads_present(self):
        ids = [bead_id for bead_id, _ in mod.SECTION_BEADS]
        for expected in [
            "bd-1l5",
            "bd-jjm",
            "bd-174",
            "bd-2ms",
            "bd-1r2",
            "bd-364",
            "bd-oty",
            "bd-2sx",
            "bd-1vp",
            "bd-13q",
            "bd-1hd",
        ]:
            self.assertIn(expected, ids)


class TestEvidencePass(unittest.TestCase):
    def test_verdict_pass(self):
        self.assertTrue(mod._evidence_pass({"verdict": "PASS"}))

    def test_overall_pass(self):
        self.assertTrue(mod._evidence_pass({"overall_pass": True}))

    def test_status_pass(self):
        self.assertTrue(mod._evidence_pass({"status": "pass"}))

    def test_status_completed_with_baseline_failures(self):
        self.assertTrue(mod._evidence_pass({"status": "completed_with_baseline_workspace_failures"}))

    def test_command_results_pass_with_fail_baseline(self):
        payload = {
            "command_results": [
                {"status": "PASS"},
                {"status": "FAIL_BASELINE"},
            ]
        }
        self.assertTrue(mod._evidence_pass(payload))

    def test_false_when_no_pass_signals(self):
        self.assertFalse(mod._evidence_pass({"status": "fail"}))


class TestRunAllChecks(unittest.TestCase):
    def test_returns_list(self):
        checks = mod.run_all_checks()
        self.assertIsInstance(checks, list)

    def test_has_many_checks(self):
        checks = mod.run_all_checks()
        self.assertGreaterEqual(len(checks), 45)

    def test_required_keys(self):
        checks = mod.run_all_checks()
        for entry in checks:
            self.assertIn("check", entry)
            self.assertIn("pass", entry)
            self.assertIn("detail", entry)

    def test_all_checks_pass(self):
        checks = mod.run_all_checks()
        failing = [c for c in checks if not c["pass"]]
        self.assertEqual(len(failing), 0, "\n".join(f"FAIL: {c['check']} :: {c['detail']}" for c in failing))


class TestRunAll(unittest.TestCase):
    def test_structure(self):
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
            "checks",
        ]:
            self.assertIn(key, result)

    def test_identity(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-1jjq")
        self.assertEqual(result["section"], "10.10")
        self.assertTrue(result["gate"])

    def test_pass_verdict(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS", self._failure_summary(result))
        self.assertTrue(result["overall_pass"])
        self.assertEqual(result["failed"], 0, self._failure_summary(result))

    def test_json_serializable(self):
        result = mod.run_all()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-1jjq")

    def _failure_summary(self, result):
        failures = [c for c in result.get("checks", []) if not c.get("pass")]
        return "\n".join(f"FAIL: {c['check']} :: {c['detail']}" for c in failures)


class TestSelfTest(unittest.TestCase):
    def test_self_test(self):
        self.assertTrue(mod.self_test())


class TestKeyChecks(unittest.TestCase):
    def test_aggregate_checks_present_and_pass(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        for check_name in [
            "all_evidence_present",
            "all_summaries_present",
            "all_specs_present",
            "all_verdicts_pass",
            "section_bead_cardinality",
        ]:
            self.assertIn(check_name, checks)
            self.assertTrue(checks[check_name]["pass"], f"{check_name}: {checks[check_name]['detail']}")

    def test_cross_bead_checks_pass(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        for check_name in [
            "cross_trust_object_prefix_coverage",
            "cross_checkpoint_prefix_alignment",
            "cross_token_chain_invariants",
            "cross_zone_segmentation_invariants",
            "cross_trust_chain_coherence",
        ]:
            self.assertIn(check_name, checks)
            self.assertTrue(checks[check_name]["pass"], f"{check_name}: {checks[check_name]['detail']}")

    def test_hardening_checks_pass(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        for check_name in [
            "hardening_session_auth",
            "hardening_revocation_freshness",
            "hardening_release_vectors",
            "hardening_error_namespace",
            "hardening_control_plane_surfaces_present",
            "hardening_mod_registration",
        ]:
            self.assertIn(check_name, checks)
            self.assertTrue(checks[check_name]["pass"], f"{check_name}: {checks[check_name]['detail']}")


if __name__ == "__main__":
    unittest.main()
