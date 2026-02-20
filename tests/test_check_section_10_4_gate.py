"""Unit tests for scripts/gate_section_10_4.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "gate_section_10_4",
    ROOT / "scripts" / "gate_section_10_4.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestGateConstants(TestCase):
    def test_has_all_expected_beads(self) -> None:
        bead_ids = [entry.bead for entry in mod.SECTION_ENTRIES]
        self.assertEqual(len(bead_ids), 8)
        self.assertIn("bd-1gx", bead_ids)
        self.assertIn("bd-phf", bead_ids)

    def test_wrapper_exists(self) -> None:
        self.assertTrue((ROOT / "scripts" / "check_section_10_4_gate.py").is_file())


class TestHelpers(TestCase):
    def test_parse_passed_failed(self) -> None:
        passed, failed = mod._parse_passed_failed("== 14 passed, 2 failed in 0.12s ==")
        self.assertEqual(passed, 14)
        self.assertEqual(failed, 2)

    def test_self_test(self) -> None:
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreaterEqual(len(checks), 3)


class TestRepositoryChecks(TestCase):
    def test_evidence_check_passes_current_repo(self) -> None:
        result = mod.check_evidence_artifacts()
        self.assertEqual(result["status"], "PASS")

    def test_policy_check_passes_current_repo(self) -> None:
        result = mod.check_policy_prereqs()
        self.assertEqual(result["status"], "PASS")

    def test_missing_evidence_fails(self) -> None:
        fake_entry = mod.SectionEntry(
            bead="bd-missing",
            name="missing",
            script="scripts/missing.py",
            test="tests/missing.py",
        )
        with patch.object(mod, "SECTION_ENTRIES", [fake_entry]):
            result = mod.check_evidence_artifacts()
        self.assertEqual(result["status"], "FAIL")


class TestReportAssembly(TestCase):
    def test_build_report_shape(self) -> None:
        script_check = {
            "id": "GATE-SCRIPTS",
            "status": "PASS",
            "details": {
                "total": 8,
                "passing": 8,
                "results": [
                    {
                        "bead": entry.bead,
                        "status": "PASS",
                        "script": entry.script,
                        "name": entry.name,
                    }
                    for entry in mod.SECTION_ENTRIES
                ],
            },
        }
        test_check = {
            "id": "GATE-TESTS",
            "status": "PASS",
            "details": {
                "results": [
                    {"bead": entry.bead, "status": "PASS", "test": entry.test}
                    for entry in mod.SECTION_ENTRIES
                ],
                "companion_test_coverage_pct": 100.0,
            },
        }
        evidence_check = {
            "id": "GATE-EVIDENCE",
            "status": "PASS",
            "details": {
                "results": [
                    {"bead": entry.bead, "status": "PASS"} for entry in mod.SECTION_ENTRIES
                ]
            },
        }
        integration_check = {
            "id": "GATE-INTEGRATION",
            "status": "PASS",
            "details": {"pipelines": [], "passing": 3, "total": 3},
        }
        policy_check = {"id": "GATE-POLICY", "status": "PASS", "details": {"results": []}}

        with (
            patch.object(mod, "run_verification_scripts", return_value=script_check),
            patch.object(mod, "run_unit_tests", return_value=test_check),
            patch.object(mod, "check_evidence_artifacts", return_value=evidence_check),
            patch.object(
                mod,
                "check_cross_bead_integrations",
                return_value=integration_check,
            ),
            patch.object(mod, "check_policy_prereqs", return_value=policy_check),
        ):
            report = mod.build_report()

        self.assertTrue(report["gate_pass"])
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["bead_id"], "bd-261k")
        self.assertEqual(len(report["per_bead_results"]), 8)
        self.assertIn("content_hash", report)


if __name__ == "__main__":
    main()
