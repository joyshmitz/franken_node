"""Unit tests for scripts/check_change_summary_contract.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_change_summary_contract",
    ROOT / "scripts" / "check_change_summary_contract.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestFixturePaths(TestCase):
    def test_template_and_example_exist(self) -> None:
        self.assertTrue(mod.TEMPLATE_PATH.is_file())
        self.assertTrue(mod.EXAMPLE_PATH.is_file())

    def test_required_event_codes_declared(self) -> None:
        self.assertIn("CONTRACT_CHANGE_SUMMARY_VALIDATED", mod.REQUIRED_EVENT_CODES)
        self.assertIn("CONTRACT_MISSING", mod.REQUIRED_EVENT_CODES)
        self.assertIn("CONTRACT_INCOMPLETE", mod.REQUIRED_EVENT_CODES)


class TestVerification(TestCase):
    def test_run_checks_passes_with_example_summary(self) -> None:
        with TemporaryDirectory(prefix="change-summary-test-") as tmp:
            changed_files = Path(tmp) / "changed_files.txt"
            changed_files.write_text(
                "\n".join(
                    [
                        "crates/franken-node/src/connector/lease_coordinator.rs",
                        "docs/change_summaries/example_change_summary.json",
                    ]
                ),
                encoding="utf-8",
            )

            ok, report = mod.run_checks(changed_files_path=changed_files)

        self.assertTrue(ok)
        self.assertEqual(report["bead_id"], "bd-3se1")
        self.assertEqual(report["subsystem_change_count"], 1)
        self.assertIn("docs/change_summaries/example_change_summary.json", report["summary_files_checked"])

    def test_missing_summary_is_rejected(self) -> None:
        with TemporaryDirectory(prefix="change-summary-test-") as tmp:
            changed_files = Path(tmp) / "changed_files.txt"
            changed_files.write_text(
                "crates/franken-node/src/connector/lease_coordinator.rs\n",
                encoding="utf-8",
            )

            ok, report = mod.run_checks(changed_files_path=changed_files)

        self.assertFalse(ok)
        self.assertTrue(
            any("missing required change summary file" in err for err in report["errors"])
        )

    def test_non_subsystem_changes_do_not_require_summary(self) -> None:
        ok, report = mod.run_checks(changed_files=["README.md"])

        self.assertTrue(ok)
        self.assertFalse(report["requires_change_summary"])
        self.assertEqual(report["summary_files_checked"], [])

    def test_incomplete_summary_is_rejected(self) -> None:
        with TemporaryDirectory(prefix="change-summary-project-") as tmp:
            project_root = Path(tmp)
            (project_root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
            (project_root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
            (project_root / "docs" / "specs").mkdir(parents=True, exist_ok=True)

            (project_root / "docs" / "templates" / "change_summary_template.md").write_text(
                "# template\n",
                encoding="utf-8",
            )
            (project_root / "docs" / "specs" / "mock_contract.md").write_text(
                "# mock contract\n",
                encoding="utf-8",
            )

            valid_payload = {
                "summary_id": "chg-test",
                "contract_version": "1.0",
                "change_summary": {
                    "intent": "Add deterministic validator.",
                    "scope": {
                        "subsystems": ["franken_node.connector"],
                        "modules": ["crates/franken-node/src/connector/lease_service.rs"],
                    },
                    "surface_area_delta": {
                        "new_apis": ["POST /v1/mock"],
                        "removed_apis": [],
                        "changed_signatures": [],
                    },
                    "affected_contracts": {
                        "beads": ["bd-3se1"],
                        "documents": ["docs/specs/mock_contract.md"],
                    },
                    "operational_impact": {
                        "operator_notes": "No user-visible downtime expected.",
                        "required_actions": ["Run validation gate in CI."],
                        "rollout_notes": "Roll out with canary first.",
                    },
                    "risk_delta": {
                        "previous_tier": "high",
                        "new_tier": "medium",
                        "rationale": "Validation narrows unsafe transitions.",
                    },
                    "compatibility": {
                        "backward_compatibility": "compatible",
                        "forward_compatibility": "enables",
                        "details": "Runtime behavior is unchanged for successful flows.",
                    },
                    "dependency_changes": {"added": [], "removed": [], "updated": []},
                },
            }

            example_path = project_root / "docs" / "change_summaries" / "example_change_summary.json"
            example_path.write_text(json.dumps(valid_payload, indent=2), encoding="utf-8")

            invalid_payload = dict(valid_payload)
            invalid_change_summary = dict(valid_payload["change_summary"])
            invalid_change_summary.pop("intent")
            invalid_payload["change_summary"] = invalid_change_summary
            invalid_path = project_root / "docs" / "change_summaries" / "invalid_summary.json"
            invalid_path.write_text(json.dumps(invalid_payload, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                changed_files=[
                    "crates/franken-node/src/connector/lease_service.rs",
                    "docs/change_summaries/invalid_summary.json",
                ],
                project_root=project_root,
            )

        self.assertFalse(ok)
        self.assertTrue(any("change_summary.intent" in err for err in report["errors"]))

    def test_self_test_passes(self) -> None:
        ok, payload = mod.self_test()
        self.assertTrue(ok)
        self.assertEqual(payload["self_test"], "passed")


if __name__ == "__main__":
    main()
