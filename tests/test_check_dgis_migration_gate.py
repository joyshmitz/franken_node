#!/usr/bin/env python3
"""Unit tests for scripts/check_dgis_migration_gate.py."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_dgis_migration_gate as checker


def _write_pass_fixture(root: Path) -> None:
    for rel in checker.REQUIRED_FILES:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if rel.endswith(".json"):
            path.write_text(
                json.dumps(
                    {
                        "plan_id": "plan-123",
                        "evaluation": {
                            "phase": "admission",
                            "verdict": "replan_required",
                            "baseline": {
                                "cascade_risk": 0.22,
                                "fragility_findings": 4,
                                "articulation_points": 2,
                            },
                            "projected": {
                                "cascade_risk": 0.40,
                                "fragility_findings": 7,
                                "articulation_points": 5,
                            },
                            "delta": {
                                "cascade_risk_delta": 0.18,
                                "new_fragility_findings": 3,
                                "new_articulation_points": 3,
                            },
                            "thresholds": {
                                "max_cascade_risk_delta": 0.12,
                                "max_new_fragility_findings": 2,
                                "max_new_articulation_points": 1,
                            },
                            "rejection_reasons": [{"code": "DGIS-MIGRATE-RISK-DELTA"}],
                            "replan_suggestions": [{"path_id": "path-a"}],
                            "events": [
                                {"code": "DGIS-MIGRATE-001"},
                                {"code": "DGIS-MIGRATE-003"},
                            ],
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        elif rel.endswith("dgis_migration_gate.rs"):
            path.write_text(
                "\n".join(checker.REQUIRED_EVENT_CODES + checker.REQUIRED_RUST_SYMBOLS),
                encoding="utf-8",
            )
        else:
            path.write_text("ok", encoding="utf-8")


class TestRequiredFiles(unittest.TestCase):
    def test_missing_files_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            checks = checker.check_required_files(Path(tmp))
            self.assertTrue(any(c["status"] == "FAIL" for c in checks))

    def test_all_files_present_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_pass_fixture(root)
            checks = checker.check_required_files(root)
            self.assertTrue(all(c["status"] == "PASS" for c in checks))


class TestRustContract(unittest.TestCase):
    def test_missing_gate_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            checks = checker.check_rust_contract(Path(tmp))
            self.assertEqual(checks[0]["status"], "FAIL")

    def test_required_symbols_and_event_codes_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_pass_fixture(root)
            checks = checker.check_rust_contract(root)
            self.assertTrue(all(c["status"] == "PASS" for c in checks))


class TestReportValidation(unittest.TestCase):
    def test_missing_report_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            checks = checker.check_report(Path(tmp))
            self.assertEqual(checks[0]["status"], "FAIL")

    def test_invalid_json_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "artifacts/10.20/dgis_migration_health_report.json"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text("{bad-json", encoding="utf-8")
            checks = checker.check_report(root)
            self.assertEqual(checks[0]["status"], "FAIL")

    def test_valid_report_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_pass_fixture(root)
            checks = checker.check_report(root)
            self.assertTrue(all(c["status"] == "PASS" for c in checks))

    def test_invalid_verdict_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_pass_fixture(root)
            report = root / "artifacts/10.20/dgis_migration_health_report.json"
            data = json.loads(report.read_text(encoding="utf-8"))
            data["evaluation"]["verdict"] = "not-valid"
            report.write_text(json.dumps(data), encoding="utf-8")
            checks = checker.check_report(root)
            verdict_checks = [c for c in checks if c["id"] == "BD2D17-REPORT-VERDICT"]
            self.assertEqual(verdict_checks[0]["status"], "FAIL")


class TestRunChecks(unittest.TestCase):
    def test_full_run_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_pass_fixture(root)
            result = checker.run_checks(root)
            self.assertEqual(result["verdict"], "PASS")
            self.assertEqual(result["summary"]["failing_checks"], 0)

    def test_full_run_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = checker.run_checks(Path(tmp))
            self.assertEqual(result["verdict"], "FAIL")
            self.assertGreater(result["summary"]["failing_checks"], 0)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        result = checker.self_test()
        self.assertEqual(result["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
