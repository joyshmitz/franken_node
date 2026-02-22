"""Unit tests for scripts/check_workflow_primitive_map.py."""

import copy
import json
import subprocess
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_workflow_primitive_map as mod


class TestContractParsing(unittest.TestCase):
    def test_parse_canonical_primitives(self):
        primitives = mod.parse_canonical_primitives(mod.DEFAULT_CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(primitives, mod.REQUIRED_PRIMITIVES)

    def test_required_workflow_set_size(self):
        self.assertGreaterEqual(len(mod.REQUIRED_WORKFLOWS), 8)


class TestRunGate(unittest.TestCase):
    def test_run_gate_passes(self):
        result = mod.run_gate(mod.DEFAULT_CONTRACT, mod.DEFAULT_MATRIX, trace_id="test-trace")
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["checks_passed"], result["checks_total"])

    def test_workflow_counts(self):
        result = mod.run_gate(mod.DEFAULT_CONTRACT, mod.DEFAULT_MATRIX, trace_id="test-trace")
        counts = result["workflow_counts"]
        self.assertEqual(counts["total"], 8)
        self.assertEqual(counts["mapped"], 8)
        self.assertEqual(counts["partial"], 0)
        self.assertEqual(counts["unmapped"], 0)

    def test_event_codes_present(self):
        result = mod.run_gate(mod.DEFAULT_CONTRACT, mod.DEFAULT_MATRIX, trace_id="test-trace")
        event_codes = {event["event_code"] for event in result["events"]}
        self.assertIn("WFM-001", event_codes)
        self.assertIn("WFM-004", event_codes)


class TestEvaluateMatrixMutations(unittest.TestCase):
    def setUp(self):
        self.canonical = mod.parse_canonical_primitives(
            mod.DEFAULT_CONTRACT.read_text(encoding="utf-8")
        )
        with mod.DEFAULT_MATRIX.open(encoding="utf-8") as handle:
            self.matrix = json.load(handle)

    def _check_lookup(self, checks, name):
        for check in checks:
            if check["check"] == name:
                return check
        return None

    def test_unknown_primitive_fails(self):
        bad = copy.deepcopy(self.matrix)
        bad["workflows"][0]["required_primitives"].append("not_a_real_primitive")

        result = mod._evaluate_matrix(bad, self.canonical, trace_id="trace-bad-primitive")
        primitive_check = self._check_lookup(result.checks, "primitive_references_known")
        self.assertIsNotNone(primitive_check)
        self.assertFalse(primitive_check["passed"])

        self.assertTrue(
            any(
                event["event_code"] == "WFM-004" and event["status"] == "fail"
                for event in result.events
            )
        )

    def test_missing_required_workflow_fails(self):
        bad = copy.deepcopy(self.matrix)
        bad["workflows"] = [
            workflow
            for workflow in bad["workflows"]
            if workflow.get("workflow_id") != "connector_lifecycle"
        ]
        bad["summary"]["total_workflows"] = len(bad["workflows"])
        bad["summary"]["fully_mapped"] = len(bad["workflows"])

        result = mod._evaluate_matrix(bad, self.canonical, trace_id="trace-missing-workflow")
        required_check = self._check_lookup(result.checks, "required_workflows_present")
        self.assertIsNotNone(required_check)
        self.assertFalse(required_check["passed"])

    def test_unmapped_without_exception_fails(self):
        bad = copy.deepcopy(self.matrix)
        bad["workflows"][0]["mapped"] = False
        bad["summary"]["fully_mapped"] -= 1
        bad["summary"]["unmapped"] += 1

        result = mod._evaluate_matrix(bad, self.canonical, trace_id="trace-unmapped-no-exception")
        mapped_check = self._check_lookup(result.checks, "critical_workflows_mapped_or_exceptioned")
        self.assertIsNotNone(mapped_check)
        self.assertFalse(mapped_check["passed"])
        self.assertTrue(
            any(
                event["event_code"] == "WFM-003" and event["status"] == "fail"
                for event in result.events
            )
        )

    def test_unmapped_with_approved_exception_passes(self):
        ok = copy.deepcopy(self.matrix)
        workflow = ok["workflows"][0]
        workflow["mapped"] = False
        workflow["exception"] = {
            "approved": True,
            "waiver_id": "WFM-EX-001",
            "reason": "temporary rollout hold",
            "expires_at": (datetime.now(UTC) + timedelta(days=7)).isoformat(),
        }
        ok["summary"]["fully_mapped"] -= 1
        ok["summary"]["partially_mapped"] += 1

        result = mod._evaluate_matrix(ok, self.canonical, trace_id="trace-unmapped-approved")
        mapped_check = self._check_lookup(result.checks, "critical_workflows_mapped_or_exceptioned")
        self.assertIsNotNone(mapped_check)
        self.assertTrue(mapped_check["passed"])
        self.assertTrue(
            any(
                event["event_code"] == "WFM-002" and event["status"] == "pass"
                for event in result.events
            )
        )


class TestSelfTest(unittest.TestCase):
    def test_self_test_returns_true(self):
        self.assertTrue(mod.self_test())


class TestCli(unittest.TestCase):
    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_workflow_primitive_map.py"), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "PASS")

    def test_cli_self_test(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_workflow_primitive_map.py"), "--self-test"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("self_test:", proc.stderr)


if __name__ == "__main__":
    unittest.main()
