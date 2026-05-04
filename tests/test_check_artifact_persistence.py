"""Unit tests for check_artifact_persistence.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

from scripts import check_artifact_persistence

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_artifact_persistence.py"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-12h8/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestArtifactFixtures(unittest.TestCase):

    def test_fixtures_exist(self):
        path = ROOT / "artifacts/section_10_13/bd-12h8/artifact_replay_fixtures.json"
        self.assertTrue(path.is_file())

    def test_fixtures_valid_json(self):
        path = ROOT / "artifacts/section_10_13/bd-12h8/artifact_replay_fixtures.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        self.assertIn("fixtures", data)
        self.assertGreaterEqual(len(data["fixtures"]), 6)

    def test_all_six_types_present(self):
        path = ROOT / "artifacts/section_10_13/bd-12h8/artifact_replay_fixtures.json"
        data = decode_json_object(path.read_text(encoding="utf-8"))
        types = {f["artifact_type"] for f in data["fixtures"]}
        for t in ["invoke", "response", "receipt", "approval", "revocation", "audit"]:
            self.assertIn(t, types, f"Missing artifact type {t}")


class TestArtifactPersistenceImpl(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/connector/artifact_persistence.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_artifact_type(self):
        self.assertIn("enum ArtifactType", self.content)

    def test_has_persisted_artifact(self):
        self.assertIn("struct PersistedArtifact", self.content)

    def test_has_replay_hook(self):
        self.assertIn("struct ReplayHook", self.content)

    def test_has_artifact_store(self):
        self.assertIn("struct ArtifactStore", self.content)

    def test_has_all_error_codes(self):
        for code in ["PRA_UNKNOWN_TYPE", "PRA_DUPLICATE", "PRA_SEQUENCE_GAP",
                     "PRA_REPLAY_MISMATCH", "PRA_INVALID_ARTIFACT"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestArtifactPersistenceSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-12h8_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-PRA-COMPLETE", "INV-PRA-DURABLE",
                    "INV-PRA-REPLAY", "INV-PRA-ORDERED"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")


class TestArtifactIntegration(unittest.TestCase):

    def setUp(self):
        self.integ_path = ROOT / "tests/integration/artifact_replay_hooks.rs"
        self.assertTrue(self.integ_path.is_file())
        self.content = self.integ_path.read_text(encoding="utf-8")

    def test_covers_complete(self):
        self.assertIn("inv_pra_complete", self.content)

    def test_covers_durable(self):
        self.assertIn("inv_pra_durable", self.content)

    def test_covers_replay(self):
        self.assertIn("inv_pra_replay", self.content)

    def test_covers_ordered(self):
        self.assertIn("inv_pra_ordered", self.content)


class TestArtifactPersistenceCli(unittest.TestCase):

    def test_json_mode_requests_full_proof_by_default(self):
        args = check_artifact_persistence.parse_args(["--json"])

        self.assertTrue(check_artifact_persistence.should_run_rust_tests(args))

    def test_structural_json_mode_is_partial_and_machine_readable(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json", "--structural-only"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        evidence = decode_json_object(result.stdout)
        statuses = {check["id"]: check["status"] for check in evidence["checks"]}

        self.assertEqual(evidence["gate"], "artifact_persistence_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(evidence["verdict"], "PARTIAL")
        self.assertEqual(statuses["PRA-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("bd-12h8:", result.stdout)

    def test_json_mode_does_not_rewrite_evidence_artifact(self):
        before = EVIDENCE_PATH.read_text(encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--json", "--structural-only"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        after = EVIDENCE_PATH.read_text(encoding="utf-8")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
