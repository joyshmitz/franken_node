"""Unit tests for check_lease_conflict.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_lease_conflict.py"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-8uvb/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestLeaseConflictFixtures(unittest.TestCase):

    def test_fixtures_exist(self):
        path = ROOT / "artifacts/section_10_13/bd-8uvb/lease_fork_log_samples.json"
        self.assertTrue(path.is_file())

    def test_fixtures_valid(self):
        path = ROOT / "artifacts/section_10_13/bd-8uvb/lease_fork_log_samples.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("scenarios", data)
        self.assertGreaterEqual(len(data["scenarios"]), 4)

    def test_fixtures_have_halt_scenario(self):
        path = ROOT / "artifacts/section_10_13/bd-8uvb/lease_fork_log_samples.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        halted = [
            s for s in data["scenarios"]
            if isinstance(s.get("expected_halted"), bool) and s["expected_halted"]
        ]
        self.assertGreater(len(halted), 0)

    def test_fixtures_have_resolved_scenario(self):
        path = ROOT / "artifacts/section_10_13/bd-8uvb/lease_fork_log_samples.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        resolved = [
            s for s in data["scenarios"]
            if isinstance(s.get("expected_halted"), bool) and not s["expected_halted"] and s.get("expected_winner")
        ]
        self.assertGreater(len(resolved), 0)


class TestLeaseConflictImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/lease_conflict.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_conflict_policy(self):
        self.assertIn("struct ConflictPolicy", self.content)

    def test_has_lease_conflict(self):
        self.assertIn("struct LeaseConflict", self.content)

    def test_has_conflict_resolution(self):
        self.assertIn("struct ConflictResolution", self.content)

    def test_has_fork_log_entry(self):
        self.assertIn("struct ForkLogEntry", self.content)

    def test_has_detect_conflicts(self):
        self.assertIn("fn detect_conflicts", self.content)

    def test_has_resolve_conflict(self):
        self.assertIn("fn resolve_conflict", self.content)

    def test_has_fork_log_entry_fn(self):
        self.assertIn("fn fork_log_entry", self.content)

    def test_has_process_conflicts(self):
        self.assertIn("fn process_conflicts", self.content)

    def test_has_all_error_codes(self):
        for code in ["OLC_DANGEROUS_HALT", "OLC_BOTH_ACTIVE",
                     "OLC_NO_WINNER", "OLC_FORK_LOG_INCOMPLETE"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestLeaseConflictSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-8uvb_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-OLC-DETERMINISTIC", "INV-OLC-DANGEROUS-HALT",
                    "INV-OLC-FORK-LOG", "INV-OLC-CLASSIFIED"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["OLC_DANGEROUS_HALT", "OLC_BOTH_ACTIVE",
                     "OLC_NO_WINNER", "OLC_FORK_LOG_INCOMPLETE"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestLeaseConflictIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = ROOT / "tests/integration/overlapping_lease_conflicts.rs"
        self.assertTrue(self.integ_path.is_file())
        self.content = self.integ_path.read_text(encoding="utf-8")

    def test_covers_deterministic(self):
        self.assertIn("inv_olc_deterministic", self.content)

    def test_covers_dangerous_halt(self):
        self.assertIn("inv_olc_dangerous_halt", self.content)

    def test_covers_fork_log(self):
        self.assertIn("inv_olc_fork_log", self.content)

    def test_covers_classified(self):
        self.assertIn("inv_olc_classified", self.content)


class TestLeaseConflictCli(unittest.TestCase):

    def test_json_mode_is_structural_and_machine_readable(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        evidence = decode_json_object(result.stdout)
        statuses = {check["id"]: check["status"] for check in evidence["checks"]}

        self.assertEqual(evidence["gate"], "lease_conflict_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(statuses["OLC-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertNotIn("bd-8uvb:", result.stdout)

    def test_json_mode_does_not_rewrite_evidence_artifact(self):
        before = EVIDENCE_PATH.read_text(encoding="utf-8")
        subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        after = EVIDENCE_PATH.read_text(encoding="utf-8")
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
