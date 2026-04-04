#!/usr/bin/env python3
"""Unit tests for scripts/reproduce.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import reproduce


def _write_claims(path: Path, procedure_ref: str, extra_fields: str = "") -> None:
    path.write_text(
        textwrap.dedent(
            f"""
            [[claim]]
            claim_id = "HC-001"
            claim_text = "sample claim"
            verification_method = "test_suite"
            acceptance_threshold = "verdict = PASS"
            test_reference = "{procedure_ref}"
            category = "compatibility"
            procedure_ref = "{procedure_ref}"
            harness_kind = "python"
            measurement_key = "verdict"
            {extra_fields}
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )


def _write_python_procedure(path: Path, payload: dict[str, object], exit_code: int = 0) -> None:
    path.write_text(
        textwrap.dedent(
            f"""
            #!/usr/bin/env python3
            import json
            import sys

            print(json.dumps({json.dumps(payload)}))
            sys.exit({exit_code})
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )


class TestReproductionRunner(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.root = Path(self.tmpdir.name)
        self.claims_path = self.root / "claims.toml"
        self.report_path = self.root / "report.json"
        self.procedure_path = self.root / "check_claim.py"

    def _patch_paths(self):
        return patch.multiple(
            reproduce,
            ROOT=self.root,
            CLAIMS_PATH=self.claims_path,
            REPORT_PATH=self.report_path,
        )

    def test_dry_run_uses_plan_schema(self) -> None:
        _write_python_procedure(self.procedure_path, {"verdict": "PASS"})
        _write_claims(self.claims_path, self.procedure_path.name)
        with self._patch_paths():
            report = reproduce.run_reproduction(dry_run=True)

        self.assertEqual(report["schema_version"], reproduce.SCHEMA_VERSION)
        self.assertEqual(report["run_mode"], "plan")
        self.assertEqual(report["verdict"], "PLANNED")
        self.assertEqual(report["claim_count"], 1)
        self.assertEqual(report["claims"][0]["execution_state"], "planned")
        self.assertEqual(report["claims"][0]["result_kind"], "not_run")
        self.assertIn("command", report["claims"][0])

    def test_executed_claim_passes_when_procedure_passes(self) -> None:
        _write_python_procedure(self.procedure_path, {"verdict": "PASS"})
        _write_claims(self.claims_path, self.procedure_path.name)
        with self._patch_paths(), patch.object(
            reproduce,
            "environment_fingerprint",
            return_value={"os": "test", "python_version": "3.11.0"},
        ):
            report = reproduce.run_reproduction()

        self.assertEqual(report["run_mode"], "executed")
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["passed_count"], 1)
        self.assertEqual(report["failed_count"], 0)
        self.assertEqual(report["error_count"], 0)
        claim = report["claims"][0]
        self.assertEqual(claim["execution_state"], "executed")
        self.assertEqual(claim["result_kind"], "pass")
        self.assertEqual(claim["measured_value"], "PASS")
        self.assertTrue(self.report_path.is_file())

    def test_executed_claim_fails_when_procedure_reports_fail(self) -> None:
        _write_python_procedure(self.procedure_path, {"verdict": "FAIL"}, exit_code=1)
        _write_claims(self.claims_path, self.procedure_path.name)
        with self._patch_paths(), patch.object(
            reproduce,
            "environment_fingerprint",
            return_value={"os": "test", "python_version": "3.11.0"},
        ):
            report = reproduce.run_reproduction()

        self.assertEqual(report["verdict"], "FAIL")
        claim = report["claims"][0]
        self.assertEqual(claim["execution_state"], "executed")
        self.assertEqual(claim["result_kind"], "fail")
        self.assertEqual(claim["measured_value"], "FAIL")
        self.assertEqual(claim["exit_code"], 1)

    def test_missing_mapping_fields_becomes_error(self) -> None:
        self.claims_path.write_text(
            textwrap.dedent(
                """
                [[claim]]
                claim_id = "HC-001"
                claim_text = "sample claim"
                verification_method = "test_suite"
                acceptance_threshold = "verdict = PASS"
                test_reference = "scripts/check_claim.py"
                category = "compatibility"
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        with self._patch_paths(), patch.object(
            reproduce,
            "environment_fingerprint",
            return_value={"os": "test", "python_version": "3.11.0"},
        ):
            report = reproduce.run_reproduction()

        self.assertEqual(report["verdict"], "ERROR")
        claim = report["claims"][0]
        self.assertEqual(claim["execution_state"], "error")
        self.assertEqual(claim["result_kind"], "error")
        self.assertIn("missing mapping fields", claim["detail"])

    def test_unknown_claim_filter_returns_error_report(self) -> None:
        _write_python_procedure(self.procedure_path, {"verdict": "PASS"})
        _write_claims(self.claims_path, self.procedure_path.name)
        with self._patch_paths():
            report = reproduce.run_reproduction(claim_filter="HC-999")

        self.assertEqual(report["verdict"], "ERROR")
        self.assertEqual(report["claim_count"], 0)
        self.assertEqual(report["error"], "unknown claim id: HC-999")

    def test_timeout_becomes_error(self) -> None:
        _write_python_procedure(self.procedure_path, {"verdict": "PASS"})
        _write_claims(self.claims_path, self.procedure_path.name)
        timeout = subprocess.TimeoutExpired(
            cmd=[sys.executable, str(self.procedure_path), "--json"],
            timeout=5,
        )
        with self._patch_paths(), patch.object(
            reproduce,
            "environment_fingerprint",
            return_value={"os": "test", "python_version": "3.11.0"},
        ), patch.object(reproduce.subprocess, "run", side_effect=timeout):
            report = reproduce.run_reproduction(timeout_seconds=5)

        self.assertEqual(report["verdict"], "ERROR")
        claim = report["claims"][0]
        self.assertEqual(claim["result_kind"], "error")
        self.assertIn("timed out", claim["detail"])
