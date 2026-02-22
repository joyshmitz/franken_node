"""Unit tests for scripts/check_canonical_vectors.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_canonical_vectors as mod


class TestRunGateOnRepository(unittest.TestCase):
    def test_gate_passes_on_repo_state(self):
        result = mod.run_gate()
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["publication_gate"]["verdict"], "PASS")

    def test_sources_present(self):
        result = mod.run_gate()
        source_ids = {source["source_id"] for source in result["sources"]}
        self.assertIn("10.13-golden-vectors", source_ids)
        self.assertIn("10.13-interop-vectors", source_ids)
        self.assertIn("10.13-fuzz-corpus", source_ids)
        self.assertIn("10.14-vector-artifacts", source_ids)

    def test_vector_sets_have_traceability(self):
        result = mod.run_gate()
        for vector_set in result["vector_sets"]:
            self.assertTrue(vector_set["source_bead_id"], vector_set["path"])
            self.assertTrue(vector_set["source_version"], vector_set["path"])

    def test_auto_discovery_covers_10_14_vectors(self):
        result = mod.run_gate()
        paths = {
            vector_set["path"]
            for vector_set in result["vector_sets"]
            if vector_set["source_id"] == "10.14-vector-artifacts"
        }
        self.assertGreaterEqual(len(paths), 4)
        self.assertIn("artifacts/10.14/idempotency_vectors.json", paths)

    def test_cross_runtime_summary_present(self):
        result = mod.run_gate()
        for vector_set in result["vector_sets"]:
            self.assertIn("cross_runtime", vector_set)
            self.assertIn("status", vector_set["cross_runtime"])


class TestTemporaryFixtures(unittest.TestCase):
    def _write_fixture(
        self,
        temp_root: Path,
        *,
        include_second_vector: bool,
        include_second_in_changelog: bool,
        second_vector_valid: bool,
    ) -> tuple[Path, Path]:
        (temp_root / "vectors").mkdir(parents=True, exist_ok=True)
        manifest_path = temp_root / "vectors" / "canonical_manifest.toml"
        changelog_path = temp_root / "vectors" / "CHANGELOG.md"

        first = temp_root / "vectors" / "alpha_vectors.json"
        first.write_text(
            json.dumps(
                {
                    "bead_id": "bd-alpha",
                    "version": "1.0.0",
                    "vectors": [{"id": "alpha-1", "implementation": "native"}],
                }
            )
            + "\n",
            encoding="utf-8",
        )

        if include_second_vector:
            second = temp_root / "vectors" / "beta_vectors.json"
            if second_vector_valid:
                second.write_text(
                    json.dumps(
                        {
                            "bead_id": "bd-beta",
                            "version": "1.0.1",
                            "vectors": [{"id": "beta-1", "implementation": "native"}],
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
            else:
                second.write_text("{ this is not valid json }\n", encoding="utf-8")

        manifest_path.write_text(
            """
version = "1.0.0"

[[sources]]
source_id = "tmp-source"
section = "10.test"
source_bead_id = "auto"
source_version = "auto"
suite_kind = "json_vectors"
required = true
globs = ["vectors/*_vectors.json"]
entry_keys = ["vectors"]
required_keys = ["vectors"]
minimum_entries = 1
parity_targets = ["native"]
publication_tag = "tmp"
""".strip()
            + "\n",
            encoding="utf-8",
        )

        changelog_lines = [
            "## [1.0.0] - 2026-02-22",
            "- Source `tmp-source`: `vectors/alpha_vectors.json`",
        ]
        if include_second_vector and include_second_in_changelog:
            changelog_lines.append("- Source `tmp-source`: `vectors/beta_vectors.json`")
        changelog_path.write_text("\n".join(changelog_lines) + "\n", encoding="utf-8")

        return manifest_path, changelog_path

    def test_newly_discovered_file_requires_changelog_entry(self):
        with tempfile.TemporaryDirectory(prefix="canonical-vectors-test-") as tmp:
            root = Path(tmp)
            manifest, changelog = self._write_fixture(
                root,
                include_second_vector=True,
                include_second_in_changelog=False,
                second_vector_valid=True,
            )
            result = mod.run_gate(manifest, changelog, root=root)
            self.assertEqual(result["verdict"], "FAIL")
            blockers = set(result["release_gate"]["blockers"])
            self.assertIn("changelog_mentions_path:vectors/beta_vectors.json", blockers)

    def test_invalid_discovered_json_blocks_release(self):
        with tempfile.TemporaryDirectory(prefix="canonical-vectors-test-") as tmp:
            root = Path(tmp)
            manifest, changelog = self._write_fixture(
                root,
                include_second_vector=True,
                include_second_in_changelog=True,
                second_vector_valid=False,
            )
            result = mod.run_gate(manifest, changelog, root=root)
            self.assertEqual(result["verdict"], "FAIL")
            self.assertIn("source:tmp-source", result["release_gate"]["blockers"])

    def test_passing_fixture_succeeds(self):
        with tempfile.TemporaryDirectory(prefix="canonical-vectors-test-") as tmp:
            root = Path(tmp)
            manifest, changelog = self._write_fixture(
                root,
                include_second_vector=True,
                include_second_in_changelog=True,
                second_vector_valid=True,
            )
            result = mod.run_gate(manifest, changelog, root=root)
            self.assertEqual(result["verdict"], "PASS")


class TestSelfTestAndCli(unittest.TestCase):
    def test_self_test(self):
        self.assertTrue(mod.self_test())

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_canonical_vectors.py"), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["bead_id"], "bd-s6y")
        self.assertEqual(payload["verdict"], "PASS")

    def test_cli_self_test(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_canonical_vectors.py"), "--self-test"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("self_test: PASS", proc.stderr)


if __name__ == "__main__":
    unittest.main()
