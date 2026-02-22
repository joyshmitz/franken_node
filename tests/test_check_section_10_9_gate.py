"""Unit tests for scripts/check_section_10_9_gate.py (bd-1kfq)."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_section_10_9_gate as gate


class TestSectionEntries(unittest.TestCase):
    def test_entry_count(self):
        self.assertEqual(len(gate.SECTION_ENTRIES), 6)

    def test_all_beads_unique(self):
        beads = [e.bead for e in gate.SECTION_ENTRIES]
        self.assertEqual(len(beads), len(set(beads)))

    def test_expected_beads(self):
        beads = {e.bead for e in gate.SECTION_ENTRIES}
        expected = {"bd-f5d", "bd-9is", "bd-1e0", "bd-m8p", "bd-10c", "bd-15t"}
        self.assertEqual(beads, expected)

    def test_all_scripts_exist(self):
        for entry in gate.SECTION_ENTRIES:
            path = ROOT / entry.script
            self.assertTrue(path.is_file(), f"script missing: {entry.script}")

    def test_all_tests_exist(self):
        for entry in gate.SECTION_ENTRIES:
            path = ROOT / entry.test
            self.assertTrue(path.is_file(), f"test missing: {entry.test}")


class TestEventCodes(unittest.TestCase):
    def test_event_code_count(self):
        self.assertEqual(len(gate.EVENT_CODES), 4)

    def test_expected_codes(self):
        expected = {
            "GATE_10_9_EVALUATION_STARTED",
            "GATE_10_9_BEAD_CHECKED",
            "GATE_10_9_MOONSHOT_COVERAGE",
            "GATE_10_9_VERDICT_EMITTED",
        }
        self.assertEqual(gate.EVENT_CODES, expected)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = gate.self_test()
        failing = [c for c in checks if not c["pass"]]
        self.assertTrue(ok, "\n".join(
            f"FAIL: {c['check']}: {c['detail']}" for c in failing
        ))

    def test_self_test_returns_checks(self):
        ok, checks = gate.self_test()
        self.assertIsInstance(checks, list)
        self.assertGreaterEqual(len(checks), 3)

    def test_self_test_check_format(self):
        _, checks = gate.self_test()
        for check in checks:
            self.assertIn("check", check)
            self.assertIn("pass", check)
            self.assertIn("detail", check)


class TestEvidenceArtifacts(unittest.TestCase):
    def test_all_evidence_exists(self):
        for entry in gate.SECTION_ENTRIES:
            path = ROOT / "artifacts" / "section_10_9" / entry.bead / "verification_evidence.json"
            self.assertTrue(path.is_file(), f"evidence missing: {entry.bead}")

    def test_all_evidence_valid_json(self):
        for entry in gate.SECTION_ENTRIES:
            path = ROOT / "artifacts" / "section_10_9" / entry.bead / "verification_evidence.json"
            if path.is_file():
                data = json.loads(path.read_text())
                self.assertIn("verdict", data, f"{entry.bead}: evidence missing verdict")


class TestHelpers(unittest.TestCase):
    def test_canonical_json_deterministic(self):
        d = {"b": 2, "a": 1, "c": [3, 4]}
        j1 = gate._canonical_json(d)
        j2 = gate._canonical_json(d)
        self.assertEqual(j1, j2)

    def test_canonical_json_sorted(self):
        d = {"z": 1, "a": 2}
        result = gate._canonical_json(d)
        self.assertTrue(result.index('"a"') < result.index('"z"'))

    def test_is_script_payload_pass_verdict(self):
        self.assertTrue(gate._is_script_payload_pass({"verdict": "PASS"}))
        self.assertFalse(gate._is_script_payload_pass({"verdict": "FAIL"}))

    def test_is_script_payload_pass_overall(self):
        self.assertTrue(gate._is_script_payload_pass({"overall_pass": True}))
        self.assertFalse(gate._is_script_payload_pass({"overall_pass": False}))

    def test_is_script_payload_pass_ok(self):
        self.assertTrue(gate._is_script_payload_pass({"ok": True}))
        self.assertFalse(gate._is_script_payload_pass({"ok": False}))

    def test_is_script_payload_pass_gate_pass(self):
        self.assertTrue(gate._is_script_payload_pass({"gate_pass": True}))
        self.assertFalse(gate._is_script_payload_pass({"gate_pass": False}))


class TestBuildReport(unittest.TestCase):
    """Integration test — runs all sub-scripts."""

    @classmethod
    def setUpClass(cls):
        cls.report = gate.build_report()

    def test_report_has_gate(self):
        self.assertEqual(self.report["gate"], "section_10_9_comprehensive_gate")

    def test_report_has_bead_id(self):
        self.assertEqual(self.report["bead_id"], "bd-1kfq")

    def test_report_has_section(self):
        self.assertEqual(self.report["section"], "10.9")

    def test_report_has_verdict(self):
        self.assertIn(self.report["verdict"], ("PASS", "FAIL"))

    def test_report_has_content_hash(self):
        self.assertEqual(len(self.report["content_hash"]), 64)

    def test_report_has_events(self):
        events = self.report["events"]
        codes = {e["event_code"] for e in events}
        self.assertIn("GATE_10_9_EVALUATION_STARTED", codes)
        self.assertIn("GATE_10_9_VERDICT_EMITTED", codes)

    def test_report_has_per_bead_results(self):
        per_bead = self.report["per_bead_results"]
        self.assertEqual(len(per_bead), 6)
        beads = {r["bead_id"] for r in per_bead}
        self.assertEqual(beads, {"bd-f5d", "bd-9is", "bd-1e0", "bd-m8p", "bd-10c", "bd-15t"})

    def test_report_checks_count(self):
        self.assertEqual(len(self.report["checks"]), 4)

    def test_report_json_serializable(self):
        parsed = json.loads(json.dumps(self.report))
        self.assertEqual(parsed["bead_id"], "bd-1kfq")


if __name__ == "__main__":
    unittest.main()
