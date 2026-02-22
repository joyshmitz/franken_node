#!/usr/bin/env python3
"""Unit tests for scripts/check_foundation_e2e_bundle.py."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_foundation_e2e_bundle.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("check_foundation_e2e_bundle", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FoundationBundleCheckerTests(unittest.TestCase):
    def setUp(self):
        self.checker = load_checker()

    def test_run_checks_shape(self):
        report = self.checker.run_checks()
        self.assertEqual(report["bead"], "bd-3k9t")
        self.assertIn(report["verdict"], {"PASS", "FAIL"})
        self.assertIn("summary", report)
        self.assertIsInstance(report["checks"], list)
        self.assertGreater(len(report["checks"]), 6)

    def test_load_json_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "invalid.json"
            p.write_text("{not-json}", encoding="utf-8")
            ok, payload = self.checker._load_json(p)
            self.assertFalse(ok)
            self.assertIsNone(payload)

    def test_evaluate_detects_missing_stage(self):
        summary = {
            "bead_id": "bd-3k9t",
            "verdict": "PASS",
            "coverage": {"clean": 1, "degraded": 1, "drifted": 1},
        }
        bundle = {
            "stage_results": [
                {
                    "stage_id": "run_surface_contract",
                    "stdout_path": "tests/e2e/foundation_bootstrap_suite.sh",
                    "stderr_path": "tests/e2e/foundation_bootstrap_suite.sh",
                }
            ],
            "replay_inputs": [
                "transplant/TRANSPLANT_LOCKFILE.sha256",
                "transplant/transplant_manifest.txt",
                "artifacts/section_bootstrap/bd-n9r/resolved_config_snapshot.json",
                "artifacts/section_bootstrap/bd-32e/init_snapshots.json",
                "artifacts/section_bootstrap/bd-1pk/doctor_checks_matrix.json",
            ],
        }
        logs = [
            {"event_code": "FB-E2E-001", "trace_id": "t"},
            {"event_code": "FB-E2E-010", "trace_id": "t"},
            {"event_code": "FB-E2E-020", "trace_id": "t"},
            {"event_code": "FB-E2E-099", "trace_id": "t"},
        ]
        checks = self.checker._evaluate(summary, bundle, logs)
        required = next(c for c in checks if c["id"] == "FBE2E-REQUIRED-STAGES")
        self.assertFalse(required["pass"])

    def test_evaluate_detects_bad_coverage(self):
        summary = {
            "bead_id": "bd-3k9t",
            "verdict": "PASS",
            "coverage": {"clean": 2, "degraded": 0, "drifted": 1},
        }
        bundle = {
            "stage_results": [
                {
                    "stage_id": sid,
                    "stdout_path": "tests/e2e/foundation_bootstrap_suite.sh",
                    "stderr_path": "tests/e2e/foundation_bootstrap_suite.sh",
                }
                for sid in self.checker.REQUIRED_STAGE_IDS
            ],
            "replay_inputs": [
                "transplant/TRANSPLANT_LOCKFILE.sha256",
                "transplant/transplant_manifest.txt",
                "artifacts/section_bootstrap/bd-n9r/resolved_config_snapshot.json",
                "artifacts/section_bootstrap/bd-32e/init_snapshots.json",
                "artifacts/section_bootstrap/bd-1pk/doctor_checks_matrix.json",
            ],
        }
        logs = [
            {"event_code": "FB-E2E-001", "trace_id": "t"},
            {"event_code": "FB-E2E-010", "trace_id": "t"},
            {"event_code": "FB-E2E-020", "trace_id": "t"},
            {"event_code": "FB-E2E-099", "trace_id": "t"},
        ]
        checks = self.checker._evaluate(summary, bundle, logs)
        coverage = next(c for c in checks if c["id"] == "FBE2E-COVERAGE")
        self.assertFalse(coverage["pass"])

    def test_log_jsonl_loader(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "log.jsonl"
            p.write_text(
                json.dumps({"event_code": "FB-E2E-001", "trace_id": "t"}) + "\n"
                + json.dumps({"event_code": "FB-E2E-099", "trace_id": "t"}) + "\n",
                encoding="utf-8",
            )
            ok, rows = self.checker._load_jsonl(p)
            self.assertTrue(ok)
            self.assertEqual(len(rows), 2)

    def test_self_test(self):
        self.checker.self_test()


if __name__ == "__main__":
    unittest.main()
