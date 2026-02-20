"""Unit tests for scripts/check_compatibility_threat_evidence.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_compatibility_threat_evidence",
    ROOT / "scripts" / "check_compatibility_threat_evidence.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def _make_valid_summary(artifact_path: str) -> dict:
    return {
        "summary_id": "chg-test-compat-threat",
        "contract_version": "1.0",
        "change_summary": {
            "compatibility_and_threat_evidence": {
                "compatibility_test_suites": [
                    {
                        "suite_name": "tests/conformance/mock.rs",
                        "pass_count": 5,
                        "fail_count": 0,
                        "artifact_path": artifact_path,
                    }
                ],
                "regression_risk_assessment": {
                    "risk_level": "medium",
                    "api_families": ["POST /v1/mock"],
                    "notes": "Adds validation on existing control path.",
                },
                "threat_vectors": [
                    {
                        "vector": "privilege_escalation",
                        "mitigation": "Boundary checks enforced before mutation.",
                    },
                    {
                        "vector": "data_exfiltration",
                        "mitigation": "Sensitive fields are redacted in logs.",
                    },
                    {
                        "vector": "denial_of_service",
                        "mitigation": "Rate limits and timeout caps applied.",
                    },
                ],
            }
        },
    }


class TestCompatibilityThreatEvidenceChecker(TestCase):
    def test_required_event_codes_present(self) -> None:
        self.assertIn("CONTRACT_COMPAT_THREAT_VALIDATED", mod.REQUIRED_EVENT_CODES)
        self.assertIn("CONTRACT_COMPAT_THREAT_MISSING", mod.REQUIRED_EVENT_CODES)
        self.assertIn("CONTRACT_COMPAT_THREAT_INCOMPLETE", mod.REQUIRED_EVENT_CODES)

    def test_run_checks_passes_with_valid_summary(self) -> None:
        with TemporaryDirectory(prefix="compat-threat-pass-") as tmp:
            root = Path(tmp)
            (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
            (root / "artifacts" / "11").mkdir(parents=True, exist_ok=True)

            (root / "docs" / "templates" / "change_summary_template.md").write_text(
                "# template\n",
                encoding="utf-8",
            )
            (root / "artifacts" / "11" / "mock_report.json").write_text(
                "{\"ok\":true}\n",
                encoding="utf-8",
            )

            summary = _make_valid_summary("artifacts/11/mock_report.json")
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
        self.assertEqual(report["bead_id"], "bd-36wa")
        self.assertEqual(report["subsystem_change_count"], 1)
        self.assertIn("docs/change_summaries/candidate.json", report["summary_files_checked"])

    def test_missing_contract_field_fails(self) -> None:
        with TemporaryDirectory(prefix="compat-threat-missing-field-") as tmp:
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
            any("compatibility_and_threat_evidence must be an object" in err for err in report["errors"])
        )

    def test_missing_required_threat_vectors_fails(self) -> None:
        with TemporaryDirectory(prefix="compat-threat-missing-vectors-") as tmp:
            root = Path(tmp)
            (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
            (root / "artifacts" / "11").mkdir(parents=True, exist_ok=True)

            (root / "docs" / "templates" / "change_summary_template.md").write_text(
                "# template\n",
                encoding="utf-8",
            )
            (root / "artifacts" / "11" / "mock_report.json").write_text(
                "{\"ok\":true}\n",
                encoding="utf-8",
            )

            summary = _make_valid_summary("artifacts/11/mock_report.json")
            summary["change_summary"]["compatibility_and_threat_evidence"]["threat_vectors"] = [
                {
                    "vector": "privilege_escalation",
                    "mitigation": "Boundary checks enforced before mutation.",
                }
            ]
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
        self.assertTrue(any("missing required vector" in err for err in report["errors"]))

    def test_missing_suite_artifact_path_fails(self) -> None:
        with TemporaryDirectory(prefix="compat-threat-missing-artifact-") as tmp:
            root = Path(tmp)
            (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)

            (root / "docs" / "templates" / "change_summary_template.md").write_text(
                "# template\n",
                encoding="utf-8",
            )

            summary = _make_valid_summary("artifacts/11/does_not_exist.json")
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
        self.assertTrue(any("artifact_path does not exist" in err for err in report["errors"]))

    def test_non_subsystem_change_does_not_require_summary(self) -> None:
        with TemporaryDirectory(prefix="compat-threat-non-subsystem-") as tmp:
            root = Path(tmp)
            (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "templates" / "change_summary_template.md").write_text(
                "# template\n",
                encoding="utf-8",
            )
            (root / "docs" / "change_summaries" / "example_change_summary.json").write_text(
                json.dumps(_make_valid_summary("docs/change_summaries/example_change_summary.json"), indent=2),
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
