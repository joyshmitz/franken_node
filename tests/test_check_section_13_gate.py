"""Unit tests for scripts/check_section_13_gate.py (bd-z7bt)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_section_13_gate",
    ROOT / "scripts" / "check_section_13_gate.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestGateConstants(TestCase):
    def test_ids(self) -> None:
        self.assertEqual(mod.BEAD_ID, "bd-z7bt")
        self.assertEqual(mod.SECTION, "13")

    def test_entry_count(self) -> None:
        self.assertEqual(len(mod.SECTION_ENTRIES), 12)
        bead_ids = [entry.bead for entry in mod.SECTION_ENTRIES]
        self.assertIn("bd-2f43", bead_ids)
        self.assertIn("bd-whxp", bead_ids)


class TestHelpers(TestCase):
    def test_parse_unittest_counts_ok(self) -> None:
        ran, failed = mod.parse_unittest_counts("Ran 12 tests in 0.02s\n\nOK")
        self.assertEqual(ran, 12)
        self.assertEqual(failed, 0)

    def test_parse_unittest_counts_failed(self) -> None:
        ran, failed = mod.parse_unittest_counts("Ran 5 tests in 0.01s\n\nFAILED (failures=2, errors=1)")
        self.assertEqual(ran, 5)
        self.assertEqual(failed, 3)

    def test_evidence_passed_variants(self) -> None:
        self.assertTrue(mod.evidence_passed({"verdict": "PASS"}))
        self.assertTrue(mod.evidence_passed({"overall_pass": True}))
        self.assertTrue(mod.evidence_passed({"overall_passed": True}))
        self.assertTrue(mod.evidence_passed({"all_passed": True}))
        self.assertTrue(mod.evidence_passed({"status": "pass"}))
        self.assertFalse(mod.evidence_passed({"verdict": "FAIL"}))

    def test_quantitative_threshold(self) -> None:
        ok, passed, total = mod._quantitative_threshold([True, True, True, True, False, False])
        self.assertTrue(ok)
        self.assertEqual(passed, 4)
        self.assertEqual(total, 6)

        bad, passed_bad, total_bad = mod._quantitative_threshold([True, True, True, False, False, False])
        self.assertFalse(bad)
        self.assertEqual(passed_bad, 3)
        self.assertEqual(total_bad, 6)


class TestReportAssembly(TestCase):
    def test_build_report_no_execution(self) -> None:
        report = mod.build_report(execute=False, write_outputs=False)
        self.assertEqual(report["bead_id"], "bd-z7bt")
        self.assertEqual(report["section"], "13")
        self.assertEqual(report["section_beads_expected"], 12)
        self.assertEqual(len(report["per_bead_results"]), 12)
        self.assertEqual(len(report["quantitative_targets"]), 6)
        self.assertIn(report["verdict"], ("PASS", "FAIL"))

    def test_report_json_serializable(self) -> None:
        report = mod.build_report(execute=False, write_outputs=False)
        blob = json.dumps(report, indent=2)
        parsed = json.loads(blob)
        self.assertEqual(parsed["bead_id"], "bd-z7bt")

    def test_self_test(self) -> None:
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreaterEqual(len(checks), 3)


if __name__ == "__main__":
    main()
