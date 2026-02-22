"""Unit tests for scripts/check_no_contract_no_merge.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_no_contract_no_merge",
    ROOT / "scripts" / "check_no_contract_no_merge.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


REQUIRED_CONTRACT_FIELDS = [
    "compatibility_and_threat_evidence",
    "ev_score_and_tier",
    "expected_loss_model",
    "fallback_trigger",
    "rollout_wedge",
    "rollback_command",
    "benchmark_and_correctness_artifacts",
]


def _seed_project(root: Path) -> None:
    (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
    (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
    (root / "artifacts" / "11").mkdir(parents=True, exist_ok=True)
    (root / "artifacts" / "section_11" / "bd-nglx").mkdir(parents=True, exist_ok=True)
    (root / "artifacts" / "section_11" / "bd-3l8d").mkdir(parents=True, exist_ok=True)

    (root / "docs" / "templates" / "change_summary_template.md").write_text(
        "# template\n",
        encoding="utf-8",
    )
    (root / "artifacts" / "11" / "mock_compat_report.json").write_text(
        "{\"ok\": true}\n",
        encoding="utf-8",
    )
    (root / "artifacts" / "section_11" / "bd-nglx" / "rollback_command_ci_test.json").write_text(
        "{\"ok\": true}\n",
        encoding="utf-8",
    )
    (root / "artifacts" / "section_11" / "bd-3l8d" / "benchmark_metrics.json").write_text(
        "{\"ok\": true}\n",
        encoding="utf-8",
    )
    (root / "artifacts" / "section_11" / "bd-3l8d" / "correctness_suite_output.txt").write_text(
        "ok\n",
        encoding="utf-8",
    )


def _write_summary(root: Path, filename: str, payload: dict) -> None:
    (root / "docs" / "change_summaries" / filename).write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8",
    )


class TestNoContractNoMergeChecker(TestCase):
    def test_required_event_codes_present(self) -> None:
        self.assertIn("CONTRACT_NO_MERGE_VALIDATED", mod.REQUIRED_EVENT_CODES)
        self.assertIn("CONTRACT_NO_MERGE_MISSING", mod.REQUIRED_EVENT_CODES)
        self.assertIn("CONTRACT_NO_MERGE_INCOMPLETE", mod.REQUIRED_EVENT_CODES)
        self.assertIn("CONTRACT_NO_MERGE_OVERRIDE", mod.REQUIRED_EVENT_CODES)

    def test_run_checks_passes_with_complete_contract(self) -> None:
        with TemporaryDirectory(prefix="no-contract-pass-") as tmp:
            root = Path(tmp)
            _seed_project(root)
            summary = mod._build_valid_summary()
            _write_summary(root, "example_change_summary.json", summary)
            _write_summary(root, "candidate.json", summary)

            ok, report = mod.run_checks(
                changed_files=[
                    "crates/franken-node/src/connector/mock.rs",
                    "docs/change_summaries/candidate.json",
                ],
                project_root=root,
            )

        self.assertTrue(ok)
        self.assertEqual(report["bead_id"], "bd-2ut3")
        self.assertIn("docs/change_summaries/candidate.json", report["summary_files_checked"])

    def test_missing_single_contract_field_fails_for_each_required_field(self) -> None:
        for field in REQUIRED_CONTRACT_FIELDS:
            with self.subTest(field=field):
                with TemporaryDirectory(prefix=f"no-contract-missing-{field}-") as tmp:
                    root = Path(tmp)
                    _seed_project(root)
                    summary = mod._build_valid_summary()
                    _write_summary(root, "example_change_summary.json", summary)

                    broken = json.loads(json.dumps(summary))
                    del broken["change_summary"][field]
                    _write_summary(root, "candidate.json", broken)

                    ok, report = mod.run_checks(
                        changed_files=[
                            "crates/franken-node/src/connector/mock.rs",
                            "docs/change_summaries/candidate.json",
                        ],
                        project_root=root,
                    )

                self.assertFalse(ok)
                self.assertTrue(any(field in err for err in report["errors"]))

    def test_missing_base_field_fails(self) -> None:
        with TemporaryDirectory(prefix="no-contract-missing-base-") as tmp:
            root = Path(tmp)
            _seed_project(root)
            summary = mod._build_valid_summary()
            _write_summary(root, "example_change_summary.json", summary)

            broken = json.loads(json.dumps(summary))
            del broken["change_summary"]["intent"]
            _write_summary(root, "candidate.json", broken)

            ok, report = mod.run_checks(
                changed_files=[
                    "crates/franken-node/src/connector/mock.rs",
                    "docs/change_summaries/candidate.json",
                ],
                project_root=root,
            )

        self.assertFalse(ok)
        self.assertTrue(any("change_summary.intent" in err for err in report["errors"]))

    def test_override_label_allows_merge_with_audit_warning(self) -> None:
        with TemporaryDirectory(prefix="no-contract-override-") as tmp:
            root = Path(tmp)
            _seed_project(root)
            summary = mod._build_valid_summary()
            _write_summary(root, "example_change_summary.json", summary)

            broken = json.loads(json.dumps(summary))
            del broken["change_summary"]["expected_loss_model"]
            _write_summary(root, "candidate.json", broken)

            ok, report = mod.run_checks(
                changed_files=[
                    "crates/franken-node/src/connector/mock.rs",
                    "docs/change_summaries/candidate.json",
                ],
                labels={"contract-override"},
                override_label="contract-override",
                project_root=root,
            )

        self.assertTrue(ok)
        self.assertTrue(report["override_applied"])
        self.assertTrue(any(event["event_code"] == "CONTRACT_NO_MERGE_OVERRIDE" for event in report["events"]))

    def test_missing_summary_for_subsystem_change_fails(self) -> None:
        with TemporaryDirectory(prefix="no-contract-missing-summary-") as tmp:
            root = Path(tmp)
            _seed_project(root)
            summary = mod._build_valid_summary()
            _write_summary(root, "example_change_summary.json", summary)

            ok, report = mod.run_checks(
                changed_files=["crates/franken-node/src/connector/mock.rs"],
                project_root=root,
            )

        self.assertFalse(ok)
        self.assertTrue(any("missing required change summary file" in err for err in report["errors"]))

    def test_non_subsystem_change_passes_without_contract(self) -> None:
        with TemporaryDirectory(prefix="no-contract-non-subsystem-") as tmp:
            root = Path(tmp)
            _seed_project(root)
            summary = mod._build_valid_summary()
            _write_summary(root, "example_change_summary.json", summary)

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
