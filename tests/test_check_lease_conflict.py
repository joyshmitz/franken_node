"""Unit tests for check_lease_conflict.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestLeaseConflictFixtures(unittest.TestCase):

    def test_fixtures_exist(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-8uvb/lease_fork_log_samples.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixtures_valid(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-8uvb/lease_fork_log_samples.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("scenarios", data)
        self.assertGreaterEqual(len(data["scenarios"]), 4)

    def test_fixtures_have_halt_scenario(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-8uvb/lease_fork_log_samples.json")
        with open(path) as f:
            data = json.load(f)
        halted = [s for s in data["scenarios"] if s.get("expected_halted") is True]
        self.assertGreater(len(halted), 0)

    def test_fixtures_have_resolved_scenario(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-8uvb/lease_fork_log_samples.json")
        with open(path) as f:
            data = json.load(f)
        resolved = [s for s in data["scenarios"] if s.get("expected_halted") is False and s.get("expected_winner")]
        self.assertGreater(len(resolved), 0)


class TestLeaseConflictImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/connector/lease_conflict.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

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
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-8uvb_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

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
        self.integ_path = os.path.join(ROOT, "tests/integration/overlapping_lease_conflicts.rs")
        self.assertTrue(os.path.isfile(self.integ_path))
        with open(self.integ_path) as f:
            self.content = f.read()

    def test_covers_deterministic(self):
        self.assertIn("inv_olc_deterministic", self.content)

    def test_covers_dangerous_halt(self):
        self.assertIn("inv_olc_dangerous_halt", self.content)

    def test_covers_fork_log(self):
        self.assertIn("inv_olc_fork_log", self.content)

    def test_covers_classified(self):
        self.assertIn("inv_olc_classified", self.content)


if __name__ == "__main__":
    unittest.main()
