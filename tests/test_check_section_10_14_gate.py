"""Unit tests for scripts/check_section_10_14_gate.py (bd-3epz)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_section_10_14_gate",
    ROOT / "scripts" / "check_section_10_14_gate.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestGateConstants(TestCase):
    def test_ids(self) -> None:
        self.assertEqual(mod.BEAD_ID, "bd-3epz")
        self.assertEqual(mod.SECTION, "10.14")

    def test_min_expected_beads(self) -> None:
        self.assertGreaterEqual(mod.MIN_EXPECTED_BEADS, 49)

    def test_coverage_threshold(self) -> None:
        self.assertGreaterEqual(mod.COVERAGE_THRESHOLD_PCT, 90.0)
        self.assertLessEqual(mod.COVERAGE_THRESHOLD_PCT, 100.0)


class TestEvidencePassed(TestCase):
    def test_verdict_pass(self) -> None:
        self.assertTrue(mod.evidence_passed({"verdict": "PASS"}))

    def test_verdict_fail(self) -> None:
        self.assertFalse(mod.evidence_passed({"verdict": "FAIL"}))

    def test_overall_pass(self) -> None:
        self.assertTrue(mod.evidence_passed({"overall_pass": True}))

    def test_all_passed(self) -> None:
        self.assertTrue(mod.evidence_passed({"all_passed": True}))

    def test_all_pass(self) -> None:
        self.assertTrue(mod.evidence_passed({"all_pass": True}))

    def test_status_pass(self) -> None:
        self.assertTrue(mod.evidence_passed({"status": "pass"}))

    def test_status_completed_with_baseline(self) -> None:
        self.assertTrue(
            mod.evidence_passed(
                {"status": "completed_with_baseline_workspace_failures"}
            )
        )

    def test_status_completed_with_repo_gate_failures(self) -> None:
        self.assertTrue(
            mod.evidence_passed(
                {"status": "completed_with_known_repo_gate_failures"}
            )
        )

    def test_status_implemented_with_blocked(self) -> None:
        self.assertTrue(
            mod.evidence_passed(
                {"status": "implemented_with_blocked_full_validation"}
            )
        )

    def test_checks_list_all_pass(self) -> None:
        self.assertTrue(
            mod.evidence_passed(
                {
                    "checks": [
                        {"check": "a", "pass": True},
                        {"check": "b", "pass": True},
                    ]
                }
            )
        )

    def test_checks_list_with_failure(self) -> None:
        self.assertFalse(
            mod.evidence_passed(
                {
                    "checks": [
                        {"check": "a", "pass": True},
                        {"check": "b", "pass": False},
                    ]
                }
            )
        )

    def test_checks_list_with_status_pass(self) -> None:
        self.assertTrue(
            mod.evidence_passed(
                {
                    "checks": [
                        {"check": "a", "status": "PASS"},
                        {"check": "b", "status": "FAIL_BASELINE"},
                    ]
                }
            )
        )

    def test_passed_failed_counts(self) -> None:
        self.assertTrue(mod.evidence_passed({"passed": 10, "failed": 0}))
        self.assertFalse(mod.evidence_passed({"passed": 10, "failed": 2}))

    def test_summary_dict(self) -> None:
        self.assertTrue(
            mod.evidence_passed(
                {"summary": {"total_checks": 7, "failing_checks": 0}}
            )
        )

    def test_summary_dict_with_failures(self) -> None:
        self.assertFalse(
            mod.evidence_passed(
                {"summary": {"total_checks": 7, "failing_checks": 1}}
            )
        )

    def test_verification_results_all_pass(self) -> None:
        self.assertTrue(
            mod.evidence_passed(
                {
                    "verification_results": {
                        "python_checks": {"verdict": "PASS"},
                        "rust_tests": {"verdict": "PASS"},
                    }
                }
            )
        )

    def test_verification_results_with_baseline_failure(self) -> None:
        self.assertTrue(
            mod.evidence_passed(
                {
                    "verification_results": {
                        "python_checks": {"verdict": "PASS"},
                        "cargo_check": {"verdict": "FAIL_BASELINE"},
                    }
                }
            )
        )

    def test_verification_results_with_actual_failure(self) -> None:
        self.assertFalse(
            mod.evidence_passed(
                {
                    "verification_results": {
                        "python_checks": {"verdict": "PASS"},
                        "cargo_check": {"verdict": "FAIL"},
                    }
                }
            )
        )

    def test_pass_with_variant(self) -> None:
        self.assertTrue(mod.evidence_passed({"verdict": "PASS_WITH_ENV_BLOCKERS"}))
        self.assertTrue(
            mod.evidence_passed({"verdict": "PASS_WITH_EXTERNAL_BLOCKERS"})
        )

    def test_empty_payload_fails(self) -> None:
        self.assertFalse(mod.evidence_passed({}))


class TestDiscoverBeads(TestCase):
    def test_returns_list(self) -> None:
        beads = mod.discover_beads()
        self.assertIsInstance(beads, list)

    def test_minimum_count(self) -> None:
        beads = mod.discover_beads()
        self.assertGreaterEqual(len(beads), mod.MIN_EXPECTED_BEADS)

    def test_all_start_with_bd(self) -> None:
        beads = mod.discover_beads()
        for bead in beads:
            self.assertTrue(bead.startswith("bd-"), f"{bead} should start with bd-")

    def test_sorted(self) -> None:
        beads = mod.discover_beads()
        self.assertEqual(beads, sorted(beads))


class TestLoadEvidence(TestCase):
    def test_existing_bead(self) -> None:
        result = mod.load_evidence("bd-nupr")
        self.assertTrue(result["evidence_exists"])
        self.assertEqual(result["status"], "PASS")

    def test_nonexistent_bead(self) -> None:
        result = mod.load_evidence("bd-nonexistent-fake")
        self.assertFalse(result["evidence_exists"])
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["verdict"], "MISSING_EVIDENCE")


class TestReportAssembly(TestCase):
    def test_build_report_no_write(self) -> None:
        report = mod.build_report(write_outputs=False)
        self.assertEqual(report["bead_id"], "bd-3epz")
        self.assertEqual(report["section"], "10.14")
        self.assertGreaterEqual(report["total_beads"], mod.MIN_EXPECTED_BEADS)
        self.assertIn(report["verdict"], ("PASS", "FAIL"))
        self.assertIn("per_bead_results", report)
        self.assertIn("gate_checks", report)
        self.assertIn("gaps", report)
        self.assertIn("events", report)
        self.assertIn("content_hash", report)

    def test_report_has_gate_checks(self) -> None:
        report = mod.build_report(write_outputs=False)
        gate_ids = [g["id"] for g in report["gate_checks"]]
        self.assertIn("GATE-10.14-BEAD-COUNT", gate_ids)
        self.assertIn("GATE-10.14-EVIDENCE-EXISTS", gate_ids)
        self.assertIn("GATE-10.14-COVERAGE-THRESHOLD", gate_ids)
        self.assertIn("GATE-10.14-ALL-BEADS", gate_ids)

    def test_report_json_serializable(self) -> None:
        report = mod.build_report(write_outputs=False)
        blob = json.dumps(report, indent=2)
        parsed = json.loads(blob)
        self.assertEqual(parsed["bead_id"], "bd-3epz")

    def test_report_events_present(self) -> None:
        report = mod.build_report(write_outputs=False)
        event_codes = [e["event_code"] for e in report["events"]]
        self.assertIn("GATE_10_14_EVALUATION_STARTED", event_codes)
        self.assertIn("GATE_10_14_VERDICT_EMITTED", event_codes)

    def test_coverage_pct_calculation(self) -> None:
        report = mod.build_report(write_outputs=False)
        if report["total_beads"] > 0:
            expected_pct = round(
                report["passing_beads"] / report["total_beads"] * 100.0, 2
            )
            self.assertAlmostEqual(report["coverage_pct"], expected_pct, places=2)


class TestSelfTest(TestCase):
    def test_self_test_passes(self) -> None:
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreaterEqual(len(checks), 13)
        for check in checks:
            self.assertIn("check", check)
            self.assertIn("pass", check)

    def test_self_test_all_named(self) -> None:
        _, checks = mod.self_test()
        names = [c["check"] for c in checks]
        self.assertEqual(len(names), len(set(names)), "Duplicate check names")


class TestCanonicalJson(TestCase):
    def test_deterministic(self) -> None:
        import hashlib

        a = hashlib.sha256(
            mod._canonical_json({"z": 1, "a": 2}).encode("utf-8")
        ).hexdigest()
        b = hashlib.sha256(
            mod._canonical_json({"a": 2, "z": 1}).encode("utf-8")
        ).hexdigest()
        self.assertEqual(a, b)


if __name__ == "__main__":
    main()
