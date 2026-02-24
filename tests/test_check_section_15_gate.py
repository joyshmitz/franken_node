"""Unit tests for scripts/check_section_15_gate.py (bd-2nre)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_section_15_gate",
    ROOT / "scripts" / "check_section_15_gate.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestGateConstants(TestCase):
    def test_ids(self) -> None:
        self.assertEqual(mod.BEAD_ID, "bd-2nre")
        self.assertEqual(mod.SECTION, "15")

    def test_entry_count(self) -> None:
        self.assertEqual(len(mod.SECTION_ENTRIES), 8)
        bead_ids = [entry.bead for entry in mod.SECTION_ENTRIES]
        self.assertIn("bd-209w", bead_ids)
        self.assertIn("bd-cv49", bead_ids)


class TestHelpers(TestCase):
    def test_parse_unittest_counts_ok(self) -> None:
        ran, failed = mod.parse_unittest_counts("Ran 9 tests in 0.01s\n\nOK")
        self.assertEqual(ran, 9)
        self.assertEqual(failed, 0)

    def test_parse_unittest_counts_failed(self) -> None:
        ran, failed = mod.parse_unittest_counts("Ran 5 tests\nFAILED (failures=2, errors=1)")
        self.assertEqual(ran, 5)
        self.assertEqual(failed, 3)

    def test_evidence_passed_variants(self) -> None:
        self.assertTrue(mod.evidence_passed({"verdict": "PASS"}))
        self.assertTrue(mod.evidence_passed({"overall_pass": True}))
        self.assertTrue(mod.evidence_passed({"status": "completed_with_baseline_workspace_failures"}))
        self.assertTrue(
            mod.evidence_passed(
                {
                    "overall_status": (
                        "pass_for_bd_cv49_contract_with_workspace_level_preexisting_failures_noted"
                    )
                }
            )
        )
        self.assertTrue(
            mod.evidence_passed(
                {"checks": [{"check": "x", "passed": True}, {"check": "y", "passed": True}]}
            )
        )
        self.assertFalse(mod.evidence_passed({"verdict": "FAIL"}))

    def test_parse_count_from_detail(self) -> None:
        self.assertEqual(mod._parse_count_from_detail("5/5 archetypes"), 5)
        self.assertEqual(mod._parse_count_from_detail("3 tiers"), 3)
        self.assertIsNone(mod._parse_count_from_detail("no count"))

    def test_metric_loaders(self) -> None:
        self.assertIsNotNone(mod._load_case_study_count())
        self.assertIsNotNone(mod._load_migration_usage_count())
        self.assertGreaterEqual(mod._load_case_study_count(), 3)
        self.assertGreaterEqual(mod._load_migration_usage_count(), 5)


class TestReportAssembly(TestCase):
    def test_build_report_no_execution(self) -> None:
        report = mod.build_report(execute=False, write_outputs=False)
        self.assertEqual(report["bead_id"], "bd-2nre")
        self.assertEqual(report["section"], "15")
        self.assertEqual(report["beads_expected"], 8)
        self.assertEqual(len(report["per_bead_results"]), 8)
        self.assertEqual(len(report["pillar_checklist"]), 7)
        self.assertEqual(len(report["adoption_metrics"]), 4)
        self.assertIn(report["verdict"], ("PASS", "FAIL"))

    def test_report_json_serializable(self) -> None:
        report = mod.build_report(execute=False, write_outputs=False)
        blob = json.dumps(report, indent=2)
        parsed = json.loads(blob)
        self.assertEqual(parsed["bead_id"], "bd-2nre")

    def test_self_test(self) -> None:
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreaterEqual(len(checks), 4)


if __name__ == "__main__":
    main()
