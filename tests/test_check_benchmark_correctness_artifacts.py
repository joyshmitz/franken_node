"""Unit tests for scripts/check_benchmark_correctness_artifacts.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_benchmark_correctness_artifacts",
    ROOT / "scripts" / "check_benchmark_correctness_artifacts.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def _make_valid_summary(benchmark_artifact: str, correctness_artifact: str) -> dict:
    return {
        "summary_id": "chg-test-benchmark-correctness",
        "contract_version": "1.0",
        "change_summary": {
            "benchmark_and_correctness_artifacts": {
                "benchmark_metrics": [
                    {
                        "metric_name": "p95_latency_ms",
                        "unit": "ms",
                        "measured_value": 31.4,
                        "baseline_value": 29.8,
                        "delta": 1.6,
                        "within_acceptable_bounds": True,
                        "artifact_path": benchmark_artifact,
                    }
                ],
                "correctness_suites": [
                    {
                        "suite_name": "tests/security/control_epoch_validity.rs",
                        "pass_count": 6,
                        "fail_count": 0,
                        "coverage_percent": 92.1,
                        "raw_output_artifact": correctness_artifact,
                    }
                ],
            }
        },
    }


class TestBenchmarkCorrectnessArtifactsChecker(TestCase):
    def test_required_event_codes_present(self) -> None:
        self.assertIn("CONTRACT_BENCH_CORRECT_VALIDATED", mod.REQUIRED_EVENT_CODES)
        self.assertIn("CONTRACT_BENCH_CORRECT_MISSING", mod.REQUIRED_EVENT_CODES)
        self.assertIn("CONTRACT_BENCH_CORRECT_INCOMPLETE", mod.REQUIRED_EVENT_CODES)

    def test_run_checks_passes_with_valid_summary(self) -> None:
        with TemporaryDirectory(prefix="bench-correct-pass-") as tmp:
            root = Path(tmp)
            (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
            (root / "artifacts" / "section_11" / "bd-3l8d").mkdir(parents=True, exist_ok=True)

            (root / "docs" / "templates" / "change_summary_template.md").write_text(
                "# template\n",
                encoding="utf-8",
            )
            benchmark_rel = "artifacts/section_11/bd-3l8d/benchmark_metrics.json"
            correctness_rel = "artifacts/section_11/bd-3l8d/correctness_suite_output.txt"
            (root / benchmark_rel).write_text("{\"ok\": true}\n", encoding="utf-8")
            (root / correctness_rel).write_text("ok\n", encoding="utf-8")

            summary = _make_valid_summary(benchmark_rel, correctness_rel)
            example = root / "docs" / "change_summaries" / "example_change_summary.json"
            example.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            candidate = root / "docs" / "change_summaries" / "candidate.json"
            candidate.write_text(json.dumps(summary, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                changed_files=[
                    "crates/franken-node/src/connector/mock.rs",
                    "docs/change_summaries/candidate.json",
                ],
                project_root=root,
            )

        self.assertTrue(ok)
        self.assertEqual(report["bead_id"], "bd-3l8d")
        self.assertIn("docs/change_summaries/candidate.json", report["summary_files_checked"])

    def test_missing_contract_field_fails(self) -> None:
        with TemporaryDirectory(prefix="bench-correct-missing-field-") as tmp:
            root = Path(tmp)
            (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)

            (root / "docs" / "templates" / "change_summary_template.md").write_text(
                "# template\n",
                encoding="utf-8",
            )

            summary = {
                "summary_id": "chg-test",
                "contract_version": "1.0",
                "change_summary": {},
            }
            example = root / "docs" / "change_summaries" / "example_change_summary.json"
            example.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            candidate = root / "docs" / "change_summaries" / "candidate.json"
            candidate.write_text(json.dumps(summary, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                changed_files=[
                    "crates/franken-node/src/connector/mock.rs",
                    "docs/change_summaries/candidate.json",
                ],
                project_root=root,
            )

        self.assertFalse(ok)
        self.assertTrue(
            any(
                "benchmark_and_correctness_artifacts must be an object" in err
                for err in report["errors"]
            )
        )

    def test_empty_benchmark_metrics_fails(self) -> None:
        with TemporaryDirectory(prefix="bench-correct-empty-benchmark-") as tmp:
            root = Path(tmp)
            (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
            (root / "artifacts" / "section_11" / "bd-3l8d").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "templates" / "change_summary_template.md").write_text(
                "# template\n",
                encoding="utf-8",
            )

            benchmark_rel = "artifacts/section_11/bd-3l8d/benchmark_metrics.json"
            correctness_rel = "artifacts/section_11/bd-3l8d/correctness_suite_output.txt"
            (root / benchmark_rel).write_text("{\"ok\": true}\n", encoding="utf-8")
            (root / correctness_rel).write_text("ok\n", encoding="utf-8")
            summary = _make_valid_summary(benchmark_rel, correctness_rel)
            summary["change_summary"]["benchmark_and_correctness_artifacts"]["benchmark_metrics"] = []

            example = root / "docs" / "change_summaries" / "example_change_summary.json"
            example.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            candidate = root / "docs" / "change_summaries" / "candidate.json"
            candidate.write_text(json.dumps(summary, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                changed_files=[
                    "crates/franken-node/src/connector/mock.rs",
                    "docs/change_summaries/candidate.json",
                ],
                project_root=root,
            )

        self.assertFalse(ok)
        self.assertTrue(any("benchmark_metrics must contain at least 1 item" in err for err in report["errors"]))

    def test_empty_correctness_suites_fails(self) -> None:
        with TemporaryDirectory(prefix="bench-correct-empty-correctness-") as tmp:
            root = Path(tmp)
            (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
            (root / "artifacts" / "section_11" / "bd-3l8d").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "templates" / "change_summary_template.md").write_text(
                "# template\n",
                encoding="utf-8",
            )

            benchmark_rel = "artifacts/section_11/bd-3l8d/benchmark_metrics.json"
            correctness_rel = "artifacts/section_11/bd-3l8d/correctness_suite_output.txt"
            (root / benchmark_rel).write_text("{\"ok\": true}\n", encoding="utf-8")
            (root / correctness_rel).write_text("ok\n", encoding="utf-8")
            summary = _make_valid_summary(benchmark_rel, correctness_rel)
            summary["change_summary"]["benchmark_and_correctness_artifacts"]["correctness_suites"] = []

            example = root / "docs" / "change_summaries" / "example_change_summary.json"
            example.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            candidate = root / "docs" / "change_summaries" / "candidate.json"
            candidate.write_text(json.dumps(summary, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                changed_files=[
                    "crates/franken-node/src/connector/mock.rs",
                    "docs/change_summaries/candidate.json",
                ],
                project_root=root,
            )

        self.assertFalse(ok)
        self.assertTrue(any("correctness_suites must contain at least 1 item" in err for err in report["errors"]))

    def test_delta_mismatch_fails(self) -> None:
        with TemporaryDirectory(prefix="bench-correct-delta-mismatch-") as tmp:
            root = Path(tmp)
            (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
            (root / "artifacts" / "section_11" / "bd-3l8d").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "templates" / "change_summary_template.md").write_text(
                "# template\n",
                encoding="utf-8",
            )

            benchmark_rel = "artifacts/section_11/bd-3l8d/benchmark_metrics.json"
            correctness_rel = "artifacts/section_11/bd-3l8d/correctness_suite_output.txt"
            (root / benchmark_rel).write_text("{\"ok\": true}\n", encoding="utf-8")
            (root / correctness_rel).write_text("ok\n", encoding="utf-8")
            summary = _make_valid_summary(benchmark_rel, correctness_rel)
            summary["change_summary"]["benchmark_and_correctness_artifacts"]["benchmark_metrics"][0]["delta"] = 2.0

            example = root / "docs" / "change_summaries" / "example_change_summary.json"
            example.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            candidate = root / "docs" / "change_summaries" / "candidate.json"
            candidate.write_text(json.dumps(summary, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                changed_files=[
                    "crates/franken-node/src/connector/mock.rs",
                    "docs/change_summaries/candidate.json",
                ],
                project_root=root,
            )

        self.assertFalse(ok)
        self.assertTrue(any("must equal measured_value - baseline_value" in err for err in report["errors"]))

    def test_missing_artifact_path_fails(self) -> None:
        with TemporaryDirectory(prefix="bench-correct-missing-artifact-") as tmp:
            root = Path(tmp)
            (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "templates" / "change_summary_template.md").write_text(
                "# template\n",
                encoding="utf-8",
            )

            summary = _make_valid_summary(
                "artifacts/section_11/bd-3l8d/missing_benchmark_metrics.json",
                "artifacts/section_11/bd-3l8d/missing_correctness_output.txt",
            )

            example = root / "docs" / "change_summaries" / "example_change_summary.json"
            example.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            candidate = root / "docs" / "change_summaries" / "candidate.json"
            candidate.write_text(json.dumps(summary, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                changed_files=[
                    "crates/franken-node/src/connector/mock.rs",
                    "docs/change_summaries/candidate.json",
                ],
                project_root=root,
            )

        self.assertFalse(ok)
        self.assertTrue(any("does not exist" in err for err in report["errors"]))

    def test_non_subsystem_change_does_not_require_summary(self) -> None:
        with TemporaryDirectory(prefix="bench-correct-non-subsystem-") as tmp:
            root = Path(tmp)
            (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "templates" / "change_summary_template.md").write_text(
                "# template\n",
                encoding="utf-8",
            )
            benchmark_rel = "artifacts/section_11/bd-3l8d/benchmark_metrics.json"
            correctness_rel = "artifacts/section_11/bd-3l8d/correctness_suite_output.txt"
            summary = _make_valid_summary(benchmark_rel, correctness_rel)
            (root / "docs" / "change_summaries" / "example_change_summary.json").write_text(
                json.dumps(summary, indent=2),
                encoding="utf-8",
            )

            ok, report = mod.run_checks(changed_files=["README.md"], project_root=root)

        self.assertTrue(ok)
        self.assertFalse(report["requires_contract"])
        self.assertEqual(report["summary_files_checked"], [])

    def test_self_test_passes(self) -> None:
        ok, payload = mod.self_test()
        self.assertTrue(ok)
        self.assertEqual(payload["self_test"], "passed")


if __name__ == "__main__":
    main()
