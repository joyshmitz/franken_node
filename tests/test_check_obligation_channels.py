"""Compatibility tests for scripts/check_obligation_channels.py."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_obligation_channels as wrapper


class TestWrapperParity(unittest.TestCase):
    def test_run_all_matches_contract(self):
        payload = wrapper.run_all()
        self.assertEqual(payload["bead_id"], "bd-2ah")
        self.assertIn("checks", payload)
        self.assertIn("verdict", payload)
        self.assertEqual(payload["verdict"], "PASS")

    def test_self_test_passes(self):
        payload = wrapper.self_test()
        self.assertEqual(payload["verdict"], "PASS")


class TestWrapperCli(unittest.TestCase):
    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_obligation_channels.py"), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["bead_id"], "bd-2ah")
        self.assertEqual(payload["verdict"], "PASS")

    def test_cli_self_test(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "check_obligation_channels.py"),
                "--self-test",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
