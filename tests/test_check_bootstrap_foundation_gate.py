#!/usr/bin/env python3
"""Unit tests for scripts/check_bootstrap_foundation_gate.py."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_bootstrap_foundation_gate.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("check_bootstrap_foundation_gate", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class BootstrapFoundationGateTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_checker()

    def test_constants(self):
        self.assertEqual(self.mod.BEAD_ID, "bd-3ohj")
        self.assertEqual(self.mod.SECTION, "bootstrap")
        self.assertIn("gate_verdict", self.mod._safe_rel(self.mod.CANONICAL_GATE_PATH))

    def test_green_payload_passes(self):
        report = self.mod.evaluate_payloads(self.mod._sample_payloads_green(), trace_id="trace-test-green")
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["summary"]["failing_checks"], 0)
        self.assertEqual(report["summary"]["failing_dimensions"], [])

    def test_partial_payload_fails_closed(self):
        report = self.mod.evaluate_payloads(self.mod._sample_payloads_partial(), trace_id="trace-test-partial")
        self.assertEqual(report["verdict"], "FAIL")
        self.assertIn("evidence", report["summary"]["failing_dimensions"])
        parse_check = next(c for c in report["checks"] if c["id"] == "BGATE-PARSE-INTEGRITY")
        self.assertFalse(parse_check["pass"])

    def test_failure_payload_has_dimension_tags(self):
        report = self.mod.evaluate_payloads(self.mod._sample_payloads_fail(), trace_id="trace-test-fail")
        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue({"baseline", "logging", "determinism"} & set(report["summary"]["failing_dimensions"]))
        self.assertGreaterEqual(len(report["events"]), len(report["checks"]) + 2)

    def test_logging_stability_fails_on_trace_drift(self):
        payloads = self.mod._sample_payloads_green()
        payloads["k9_log"].append({"trace_id": "drift", "event_code": "FB-E2E-099"})
        report = self.mod.evaluate_payloads(payloads, trace_id="trace-test-log-drift")
        log_check = next(c for c in report["checks"] if c["id"] == "BGATE-LOG-STABILITY")
        self.assertFalse(log_check["pass"])

    def test_docs_navigation_fails_when_gate_path_mismatch(self):
        payloads = self.mod._sample_payloads_green()
        payloads["matrix_json"]["gate_consumption"]["evidence_path"] = "artifacts/wrong/path.json"
        report = self.mod.evaluate_payloads(payloads, trace_id="trace-test-docs")
        docs_check = next(c for c in report["checks"] if c["id"] == "BGATE-MATRIX-COVERAGE-CONTRACT")
        self.assertFalse(docs_check["pass"])
        self.assertEqual(report["verdict"], "FAIL")

    def test_load_inputs_shape(self):
        payloads = self.mod.load_inputs_from_files()
        self.assertIn("parse_errors", payloads)
        self.assertIn("source_paths", payloads)
        self.assertIn("k9_summary", payloads)
        self.assertIn("a2_baseline", payloads)

    def test_report_json_serializable(self):
        report = self.mod.evaluate_payloads(self.mod._sample_payloads_green(), trace_id="trace-test-json")
        blob = json.dumps(report, indent=2)
        parsed = json.loads(blob)
        self.assertEqual(parsed["bead_id"], "bd-3ohj")
        self.assertIn(parsed["verdict"], {"PASS", "FAIL"})

    def test_self_test(self):
        ok, checks = self.mod.self_test()
        self.assertTrue(ok)
        self.assertGreaterEqual(len(checks), 5)
        for check in checks:
            self.assertIn("check", check)
            self.assertIn("pass", check)


if __name__ == "__main__":
    unittest.main()
