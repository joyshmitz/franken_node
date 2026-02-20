#!/usr/bin/env python3
"""Unit tests for guard_dependency_direction.py."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "guard_dependency_direction.py"


class TestDependencyDirectionGuard(unittest.TestCase):
    """Test dependency-direction guard checks."""

    def _run(self, json_flag=True):
        args = [sys.executable, str(SCRIPT)]
        if json_flag:
            args.append("--json")
        result = subprocess.run(args, capture_output=True, text=True, timeout=30)
        return result

    def test_script_runs_json(self):
        """Script should run and produce valid JSON."""
        result = self._run()
        self.assertEqual(result.returncode, 0, f"Failed: {result.stderr}")
        output = json.loads(result.stdout)
        self.assertIn("verdict", output)

    def test_verdict_is_pass(self):
        """Current repo should pass all guards."""
        result = self._run()
        output = json.loads(result.stdout)
        self.assertEqual(output["verdict"], "PASS")

    def test_all_checks_present(self):
        """All 4 guard checks should be present."""
        result = self._run()
        output = json.loads(result.stdout)
        check_ids = {c["id"] for c in output["checks"]}
        expected = {"GUARD-WS-MEMBERS", "GUARD-PKG-NAMES", "GUARD-DEP-DIR", "GUARD-CRATES-CLEAN"}
        self.assertEqual(check_ids, expected)

    def test_workspace_members_clean(self):
        """No engine crate dirs in workspace members."""
        result = self._run()
        output = json.loads(result.stdout)
        check = next(c for c in output["checks"] if c["id"] == "GUARD-WS-MEMBERS")
        self.assertEqual(check["status"], "PASS")

    def test_no_engine_package_names(self):
        """No local Cargo.toml declares engine package names."""
        result = self._run()
        output = json.loads(result.stdout)
        check = next(c for c in output["checks"] if c["id"] == "GUARD-PKG-NAMES")
        self.assertEqual(check["status"], "PASS")

    def test_dependency_direction_valid(self):
        """Engine deps point outside this repo."""
        result = self._run()
        output = json.loads(result.stdout)
        check = next(c for c in output["checks"] if c["id"] == "GUARD-DEP-DIR")
        self.assertEqual(check["status"], "PASS")
        # Should have found engine deps
        self.assertGreater(check["details"]["deps_checked"], 0)

    def test_crates_dir_clean(self):
        """No engine-named dirs in crates/."""
        result = self._run()
        output = json.loads(result.stdout)
        check = next(c for c in output["checks"] if c["id"] == "GUARD-CRATES-CLEAN")
        self.assertEqual(check["status"], "PASS")

    def test_human_readable_output(self):
        """Non-JSON output works."""
        result = self._run(json_flag=False)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Dependency-Direction Guard", result.stdout)
        self.assertIn("Verdict: PASS", result.stdout)

    def test_summary_counts(self):
        """Summary has correct counts."""
        result = self._run()
        output = json.loads(result.stdout)
        self.assertEqual(output["summary"]["total_checks"], 4)
        self.assertEqual(output["summary"]["passing_checks"], 4)
        self.assertEqual(output["summary"]["failing_checks"], 0)


if __name__ == "__main__":
    unittest.main()
