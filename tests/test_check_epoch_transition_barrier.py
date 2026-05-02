"""Tests for scripts/check_epoch_transition_barrier.py (bd-2wsm)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_epoch_transition_barrier.py"
sys.path.insert(0, str(ROOT / "scripts"))

import check_epoch_transition_barrier as mod  # noqa: E402


def decode_json(payload: str) -> dict:
    decoded = json.JSONDecoder().decode(payload)
    if not isinstance(decoded, dict):
        raise TypeError("expected JSON object")
    return decoded


class SelfTestTests(unittest.TestCase):
    def test_self_test_passes(self):
        self.assertTrue(mod.self_test())


class JsonOutputTests(unittest.TestCase):
    def run_json(self) -> dict:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return decode_json(result.stdout)

    def test_json_output(self):
        data = self.run_json()
        self.assertEqual(data["bead_id"], "bd-2wsm")
        self.assertEqual(data["section"], "10.14")
        self.assertIsInstance(data["checks"], list)

    def test_verdict_field(self):
        self.assertIn(self.run_json()["verdict"], ("PASS", "FAIL"))

    def test_checks_have_fields(self):
        for check in self.run_json()["checks"]:
            self.assertIn("check", check)
            self.assertIn("passed", check)
            self.assertIn("detail", check)

    def test_minimum_check_count(self):
        self.assertGreaterEqual(len(self.run_json()["checks"]), 25)


class IndividualCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = {result["check"]: result for result in mod._checks()}

    def assert_passed(self, name: str) -> None:
        self.assertTrue(self.results[name]["passed"], name)

    def test_source_exists(self):
        self.assert_passed("source_exists")

    def test_module_wiring(self):
        self.assert_passed("module_wiring")

    def test_struct_barrier_phase(self):
        self.assert_passed("struct_BarrierPhase")

    def test_struct_drain_ack(self):
        self.assert_passed("struct_DrainAck")

    def test_struct_abort_reason(self):
        self.assert_passed("struct_AbortReason")

    def test_struct_barrier_error(self):
        self.assert_passed("struct_BarrierError")

    def test_struct_barrier_config(self):
        self.assert_passed("struct_BarrierConfig")

    def test_struct_transcript_entry(self):
        self.assert_passed("struct_TranscriptEntry")

    def test_struct_barrier_transcript(self):
        self.assert_passed("struct_BarrierTranscript")

    def test_struct_barrier_audit_record(self):
        self.assert_passed("struct_BarrierAuditRecord")

    def test_struct_barrier_instance(self):
        self.assert_passed("struct_BarrierInstance")

    def test_struct_epoch_transition_barrier(self):
        self.assert_passed("struct_EpochTransitionBarrier")

    def test_phase_proposed(self):
        self.assert_passed("phase_proposed")

    def test_phase_draining(self):
        self.assert_passed("phase_draining")

    def test_phase_committed(self):
        self.assert_passed("phase_committed")

    def test_phase_aborted(self):
        self.assert_passed("phase_aborted")

    def test_fn_propose(self):
        self.assert_passed("fn_propose")

    def test_fn_record_drain_ack(self):
        self.assert_passed("fn_record_drain_ack")

    def test_fn_try_commit(self):
        self.assert_passed("fn_try_commit")

    def test_fn_abort(self):
        self.assert_passed("fn_abort")

    def test_fn_record_drain_failure(self):
        self.assert_passed("fn_record_drain_failure")

    def test_fn_check_participant_timeouts(self):
        self.assert_passed("fn_check_participant_timeouts")

    def test_fn_register_participant(self):
        self.assert_passed("fn_register_participant")

    def test_all_acked(self):
        self.assert_passed("all_acked")

    def test_missing_acks(self):
        self.assert_passed("missing_acks")

    def test_is_terminal(self):
        self.assert_passed("is_terminal")

    def test_is_barrier_active(self):
        self.assert_passed("is_barrier_active")

    def test_configurable_timeout(self):
        self.assert_passed("configurable_timeout")

    def test_transcript_export(self):
        self.assert_passed("transcript_export")

    def test_audit_log(self):
        self.assert_passed("audit_log")

    def test_event_codes(self):
        self.assert_passed("event_codes")

    def test_error_codes(self):
        self.assert_passed("error_codes")

    def test_invariants(self):
        self.assert_passed("invariants")

    def test_config_validation(self):
        self.assert_passed("config_validation")

    def test_schema_version(self):
        self.assert_passed("schema_version")

    def test_spec_alignment(self):
        self.assert_passed("spec_alignment")

    def test_test_coverage(self):
        self.assert_passed("test_coverage")


class FailureModeTests(unittest.TestCase):
    def test_missing_source_fails_closed_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "missing.rs"
            original = mod.IMPL
            try:
                mod.IMPL = missing
                checks = {result["check"]: result for result in mod._checks()}
            finally:
                mod.IMPL = original

        self.assertFalse(checks["source_exists"]["passed"])
        self.assertFalse(checks["test_coverage"]["passed"])


class OverallTests(unittest.TestCase):
    def test_all_checks_pass(self):
        failed = [result for result in mod._checks() if not result["passed"]]
        self.assertEqual([], failed, f"Failed: {[result['check'] for result in failed]}")

    def test_verdict_is_pass(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(decode_json(result.stdout)["verdict"], "PASS")

    def test_human_output(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bd-2wsm", result.stdout)
        self.assertIn("PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
