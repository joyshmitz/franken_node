"""Tests for scripts/check_migration_cohort_validation.py (bd-sxt5)."""

import json
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_migration_cohort_validation.py"


class ScriptNamespace:
    def __init__(self, script_globals: dict[str, object]) -> None:
        object.__setattr__(self, "_script_globals", script_globals)

    def __getattr__(self, name: str) -> object:
        return self._script_globals[name]


mcv = ScriptNamespace(runpy.run_path(str(SCRIPT)))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REQUIRED_ARCHETYPES = mcv.REQUIRED_ARCHETYPES


def _make_project(
    archetype="web-server-express",
    pass_rate=100.0,
    flaky=0.0,
    runs=5,
    known_incompat=None,
):
    return {
        "archetype": archetype,
        "pinned_ref": {"repo": "https://example.com/repo", "commit": "abc123def456"},
        "baseline": {"total_tests": 100, "passed": 100, "failed": 0, "status": "pass"},
        "migration": {
            "audit_report": "a.json",
            "rewrite_report": "r.json",
            "lockstep_report": "l.json",
            "rollback_artifact": "rb.json",
        },
        "post_migration": {
            "pass_rate_pct": pass_rate,
            "known_incompatibilities": known_incompat or [],
        },
        "repeated_runs": {
            "runs": runs,
            "identical_outcomes_runs": runs,
            "flaky_rate_pct": flaky,
        },
    }


def _make_valid_data():
    return {
        "projects": [_make_project(archetype=a) for a in REQUIRED_ARCHETYPES],
        "aggregate": {
            "cohort_size": 10,
            "cohort_success_rate_pct": 100.0,
            "determinism_verified": True,
            "ci_reproducible": True,
        },
    }


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        self.assertTrue(mcv.self_test())


class TestCanonicalJson(unittest.TestCase):
    def test_canonical_json_key_order(self):
        h1 = mcv._canonical_json({"z": 1, "a": 2})
        h2 = mcv._canonical_json({"a": 2, "z": 1})
        self.assertEqual(h1, h2)


class TestCheckResultsStructure(unittest.TestCase):
    def _check(self, checks, check_id):
        return next(check for check in checks if check["id"] == check_id)

    def test_valid_data_all_pass(self):
        checks = mcv._check_results_structure(_make_valid_data())
        self.assertTrue(all(check["pass"] for check in checks), [check for check in checks if not check["pass"]])

    def test_too_few_projects(self):
        data = _make_valid_data()
        data["projects"] = data["projects"][:5]
        checks = mcv._check_results_structure(data)
        cohort_check = self._check(checks, "cohort_size")
        self.assertFalse(cohort_check["pass"])

    def test_missing_archetype(self):
        data = _make_valid_data()
        # Replace one archetype with a duplicate
        data["projects"][0]["archetype"] = data["projects"][1]["archetype"]
        checks = mcv._check_results_structure(data)
        arch_check = self._check(checks, "archetype_coverage")
        self.assertFalse(arch_check["pass"])

    def test_missing_pinned_ref(self):
        data = _make_valid_data()
        data["projects"][0]["pinned_ref"] = {"repo": "", "commit": ""}
        checks = mcv._check_results_structure(data)
        pin_check = self._check(checks, "version_pinning")
        self.assertFalse(pin_check["pass"])

    def test_missing_baseline(self):
        data = _make_valid_data()
        data["projects"][0]["baseline"]["total_tests"] = 0
        checks = mcv._check_results_structure(data)
        bl_check = self._check(checks, "baseline_complete")
        self.assertFalse(bl_check["pass"])

    def test_baseline_fail_status(self):
        data = _make_valid_data()
        data["projects"][0]["baseline"]["status"] = "fail"
        checks = mcv._check_results_structure(data)
        bl_check = self._check(checks, "baseline_complete")
        self.assertFalse(bl_check["pass"])

    def test_missing_migration_artifact(self):
        data = _make_valid_data()
        data["projects"][0]["migration"]["audit_report"] = ""
        checks = mcv._check_results_structure(data)
        mig_check = self._check(checks, "migration_artifacts")
        self.assertFalse(mig_check["pass"])

    def test_non_deterministic_runs(self):
        data = _make_valid_data()
        data["projects"][0]["repeated_runs"]["flaky_rate_pct"] = 5.0
        checks = mcv._check_results_structure(data)
        det_check = self._check(checks, "deterministic_runs")
        self.assertFalse(det_check["pass"])

    def test_too_few_runs(self):
        data = _make_valid_data()
        data["projects"][0]["repeated_runs"]["runs"] = 1
        checks = mcv._check_results_structure(data)
        det_check = self._check(checks, "deterministic_runs")
        self.assertFalse(det_check["pass"])

    def test_low_pass_rate_with_incompatibilities_passes(self):
        data = _make_valid_data()
        data["projects"][0]["post_migration"]["pass_rate_pct"] = 90.0
        data["projects"][0]["post_migration"]["known_incompatibilities"] = [
            {"test": "test_x", "reason": "known issue"}
        ]
        checks = mcv._check_results_structure(data)
        pps_check = self._check(checks, "per_project_success")
        self.assertTrue(pps_check["pass"])

    def test_low_pass_rate_without_incompatibilities_fails(self):
        data = _make_valid_data()
        data["projects"][0]["post_migration"]["pass_rate_pct"] = 90.0
        data["projects"][0]["post_migration"]["known_incompatibilities"] = []
        checks = mcv._check_results_structure(data)
        pps_check = self._check(checks, "per_project_success")
        self.assertFalse(pps_check["pass"])

    def test_low_cohort_success_rate(self):
        data = _make_valid_data()
        data["aggregate"]["cohort_success_rate_pct"] = 50.0
        checks = mcv._check_results_structure(data)
        csr_check = self._check(checks, "cohort_success_rate")
        self.assertFalse(csr_check["pass"])

    def test_ci_flags_missing(self):
        data = _make_valid_data()
        data["aggregate"]["determinism_verified"] = False
        checks = mcv._check_results_structure(data)
        ci_check = self._check(checks, "ci_reproducibility")
        self.assertFalse(ci_check["pass"])

    def test_ci_flags_reject_truthy_strings(self):
        data = _make_valid_data()
        data["aggregate"]["determinism_verified"] = "true"
        checks = mcv._check_results_structure(data)
        ci_check = self._check(checks, "ci_reproducibility")
        self.assertFalse(ci_check["pass"])


class TestBuildReport(unittest.TestCase):
    def test_build_report_no_execution_structure(self):
        report = mcv.build_report(execute=False)
        self.assertIn("bead_id", report)
        self.assertEqual(report["bead_id"], "bd-sxt5")
        self.assertIn("verdict", report)
        self.assertIn("checks", report)
        self.assertIn("content_hash", report)
        self.assertIsInstance(report["checks_passed"], int)
        self.assertIsInstance(report["checks_total"], int)

    def test_build_report_no_execution_passes(self):
        """If all artifacts exist, no-exec report should pass."""
        if not mcv.RESULTS_FILE.exists():
            self.skipTest("artifacts not present")
        report = mcv.build_report(execute=False)
        self.assertEqual(report["verdict"], "PASS")

    def test_build_report_with_execution(self):
        """Full report with E2E execution."""
        if not mcv.E2E_SCRIPT.exists() or not mcv.RESULTS_FILE.exists():
            self.skipTest("artifacts or E2E script not present")
        with tempfile.TemporaryDirectory(prefix="mcv-e2e-") as temp_dir:
            output_dir = Path(temp_dir)
            env = os.environ.copy()
            env.update(
                {
                    "MIGRATION_COHORT_RESULTS_FILE": str(mcv.RESULTS_FILE),
                    "MIGRATION_COHORT_LOG_FILE": str(output_dir / "validation_log.jsonl"),
                    "MIGRATION_COHORT_SUMMARY_FILE": str(output_dir / "validation_summary.json"),
                }
            )
            report = mcv.build_report(execute=True, e2e_env=env)
            self.assertEqual(report["verdict"], "PASS")
            e2e_check = next((check for check in report["checks"] if check["id"] == "e2e_execution"), None)
            self.assertIsNotNone(e2e_check)
            self.assertTrue(e2e_check["pass"])
            self.assertTrue((output_dir / "validation_log.jsonl").is_file())
            self.assertTrue((output_dir / "validation_summary.json").is_file())


class TestCliOutput(unittest.TestCase):
    def test_json_cli_output(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json", "--no-exec"],
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
        parsed = json.JSONDecoder().decode(proc.stdout)
        self.assertEqual(parsed["bead_id"], "bd-sxt5")
        self.assertEqual(parsed["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
