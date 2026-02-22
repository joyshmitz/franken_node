#!/usr/bin/env python3
"""Unit tests for scripts/check_foundation_gate.py."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_foundation_gate.py"


def load_checker():
    spec = importlib.util.spec_from_file_location("check_foundation_gate", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _write_evidence(bead_dir: Path, bead_id: str, verdict: str = "PASS", extra: dict | None = None):
    """Helper: write a synthetic verification_evidence.json."""
    bead_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "bead_id": bead_id,
        "section": "bootstrap",
        "verdict": verdict,
    }
    if extra:
        data.update(extra)
    (bead_dir / "verification_evidence.json").write_text(
        json.dumps(data), encoding="utf-8"
    )


def _create_key_artifacts(root: Path, checker):
    """Helper: create all required key artifacts."""
    for rel in checker.KEY_ARTIFACTS:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("stub content", encoding="utf-8")


class TestSelfTest(unittest.TestCase):
    def setUp(self):
        self.checker = load_checker()

    def test_self_test(self):
        """The built-in self_test() should complete without assertion errors."""
        self.checker.self_test()


class TestAllEvidencePass(unittest.TestCase):
    def setUp(self):
        self.checker = load_checker()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.art_dir = self.tmp / "artifacts" / "section_bootstrap"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_all_evidence_pass(self):
        """Gate passes when all bead evidence files have verdict PASS."""
        for bead_id in ["bd-aaa", "bd-bbb", "bd-ccc", "bd-ddd"]:
            _write_evidence(self.art_dir / bead_id, bead_id, "PASS")
        _create_key_artifacts(self.tmp, self.checker)

        report = self.checker.run_checks(artifacts_dir=self.art_dir, root=self.tmp)

        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["summary"]["beads_discovered"], 4)
        self.assertEqual(report["summary"]["beads_passed"], 4)
        self.assertEqual(report["summary"]["beads_failed"], 0)
        self.assertTrue(report["summary"]["key_artifacts_present"])
        for dim, status in report["summary"]["dimensions"].items():
            self.assertEqual(status, "PASS", f"dimension {dim} should be PASS")

    def test_pass_report_has_bead_results(self):
        """Per-bead results are included in the report."""
        for bead_id in ["bd-xx1", "bd-xx2"]:
            _write_evidence(self.art_dir / bead_id, bead_id, "PASS")
        _create_key_artifacts(self.tmp, self.checker)

        report = self.checker.run_checks(artifacts_dir=self.art_dir, root=self.tmp)
        self.assertEqual(len(report["bead_results"]), 2)
        for br in report["bead_results"]:
            self.assertEqual(br["verdict"], "PASS")

    def test_pass_report_has_event_log(self):
        """Event log includes start, bead scans, artifact check, and verdict."""
        _write_evidence(self.art_dir / "bd-one", "bd-one", "PASS")
        _create_key_artifacts(self.tmp, self.checker)

        report = self.checker.run_checks(artifacts_dir=self.art_dir, root=self.tmp)
        codes = [e["event_code"] for e in report["event_log"]]
        self.assertIn("BOOT-GATE-001", codes)
        self.assertIn("BOOT-GATE-002", codes)
        self.assertIn("BOOT-GATE-003", codes)
        self.assertIn("BOOT-GATE-004", codes)
        # No BOOT-GATE-005 when passing
        self.assertNotIn("BOOT-GATE-005", codes)


class TestMissingEvidenceFails(unittest.TestCase):
    def setUp(self):
        self.checker = load_checker()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.art_dir = self.tmp / "artifacts" / "section_bootstrap"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_missing_evidence_fails(self):
        """Gate fails when a bead directory has no verification_evidence.json."""
        # One bead with evidence, one without.
        _write_evidence(self.art_dir / "bd-good", "bd-good", "PASS")
        bad_dir = self.art_dir / "bd-bad"
        bad_dir.mkdir(parents=True)
        # No evidence file written for bd-bad.

        _create_key_artifacts(self.tmp, self.checker)

        report = self.checker.run_checks(artifacts_dir=self.art_dir, root=self.tmp)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(report["summary"]["beads_failed"], 1)

        # Check that the failing bead is identified.
        bad_result = next(r for r in report["bead_results"] if r["bead_id"] == "bd-bad")
        self.assertEqual(bad_result["verdict"], "FAIL")
        self.assertIn("missing", bad_result["detail"].lower())

    def test_no_beads_at_all_fails(self):
        """Gate fails when the artifacts directory has no bead directories."""
        self.art_dir.mkdir(parents=True)
        _create_key_artifacts(self.tmp, self.checker)

        report = self.checker.run_checks(artifacts_dir=self.art_dir, root=self.tmp)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(report["summary"]["beads_discovered"], 0)

    def test_nonexistent_artifacts_dir_fails(self):
        """Gate fails when the artifacts directory does not exist."""
        _create_key_artifacts(self.tmp, self.checker)
        missing_dir = self.tmp / "nonexistent"

        report = self.checker.run_checks(artifacts_dir=missing_dir, root=self.tmp)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(report["summary"]["beads_discovered"], 0)


class TestFailedVerdictFails(unittest.TestCase):
    def setUp(self):
        self.checker = load_checker()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.art_dir = self.tmp / "artifacts" / "section_bootstrap"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_failed_verdict_fails(self):
        """Gate fails when any bead evidence has verdict FAIL."""
        _write_evidence(self.art_dir / "bd-ok1", "bd-ok1", "PASS")
        _write_evidence(self.art_dir / "bd-ok2", "bd-ok2", "PASS")
        _write_evidence(self.art_dir / "bd-bad", "bd-bad", "FAIL")
        _create_key_artifacts(self.tmp, self.checker)

        report = self.checker.run_checks(artifacts_dir=self.art_dir, root=self.tmp)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(report["summary"]["beads_passed"], 2)
        self.assertEqual(report["summary"]["beads_failed"], 1)
        self.assertEqual(report["summary"]["dimensions"]["upstream_verdicts"], "FAIL")

        # Remediation event should be present.
        codes = [e["event_code"] for e in report["event_log"]]
        self.assertIn("BOOT-GATE-005", codes)

    def test_mixed_verdicts_reports_per_bead(self):
        """Per-bead results correctly classify pass and fail."""
        _write_evidence(self.art_dir / "bd-alpha", "bd-alpha", "PASS")
        _write_evidence(self.art_dir / "bd-beta", "bd-beta", "FAIL")
        _create_key_artifacts(self.tmp, self.checker)

        report = self.checker.run_checks(artifacts_dir=self.art_dir, root=self.tmp)
        alpha = next(r for r in report["bead_results"] if r["bead_id"] == "bd-alpha")
        beta = next(r for r in report["bead_results"] if r["bead_id"] == "bd-beta")
        self.assertEqual(alpha["verdict"], "PASS")
        self.assertEqual(beta["verdict"], "FAIL")


class TestMissingRequiredFields(unittest.TestCase):
    def setUp(self):
        self.checker = load_checker()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.art_dir = self.tmp / "artifacts" / "section_bootstrap"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_missing_required_fields(self):
        """Gate fails when evidence has bead_id but no passing verdict signal."""
        # Complete evidence for one bead.
        _write_evidence(self.art_dir / "bd-ok", "bd-ok", "PASS")

        # Evidence with bead_id but no verdict, overall_status, or nested verdict.
        bad_dir = self.art_dir / "bd-incomplete"
        bad_dir.mkdir(parents=True)
        (bad_dir / "verification_evidence.json").write_text(
            json.dumps({"bead_id": "bd-incomplete"}),
            encoding="utf-8",
        )

        _create_key_artifacts(self.tmp, self.checker)

        report = self.checker.run_checks(artifacts_dir=self.art_dir, root=self.tmp)
        self.assertEqual(report["verdict"], "FAIL")

        bad_result = next(r for r in report["bead_results"] if r["bead_id"] == "bd-incomplete")
        self.assertEqual(bad_result["verdict"], "FAIL")
        self.assertIn("not PASS", bad_result["detail"])

    def test_truly_missing_bead_id_causes_required_field_failure(self):
        """Evidence completely missing bead_id triggers the required-fields check."""
        bad_dir = self.art_dir / "bd-noid2"
        bad_dir.mkdir(parents=True)
        (bad_dir / "verification_evidence.json").write_text(
            json.dumps({"verdict": "PASS"}),
            encoding="utf-8",
        )
        _create_key_artifacts(self.tmp, self.checker)

        report = self.checker.run_checks(artifacts_dir=self.art_dir, root=self.tmp)
        self.assertEqual(report["verdict"], "FAIL")
        bad_result = next(r for r in report["bead_results"] if r["bead_id"] == "bd-noid2")
        self.assertEqual(bad_result["verdict"], "FAIL")
        self.assertIn("missing required fields", bad_result["detail"])

    def test_missing_bead_id_field(self):
        """Evidence missing bead_id is detected."""
        bad_dir = self.art_dir / "bd-noid"
        bad_dir.mkdir(parents=True)
        (bad_dir / "verification_evidence.json").write_text(
            json.dumps({"section": "bootstrap", "verdict": "PASS"}),
            encoding="utf-8",
        )
        _create_key_artifacts(self.tmp, self.checker)

        report = self.checker.run_checks(artifacts_dir=self.art_dir, root=self.tmp)
        self.assertEqual(report["verdict"], "FAIL")
        bad_result = next(r for r in report["bead_results"] if r["bead_id"] == "bd-noid")
        self.assertEqual(bad_result["verdict"], "FAIL")
        self.assertIn("bead_id", bad_result["detail"])

    def test_invalid_json_evidence(self):
        """Evidence that is not valid JSON causes a failure."""
        bad_dir = self.art_dir / "bd-badjson"
        bad_dir.mkdir(parents=True)
        (bad_dir / "verification_evidence.json").write_text(
            "{not valid json",
            encoding="utf-8",
        )
        _create_key_artifacts(self.tmp, self.checker)

        report = self.checker.run_checks(artifacts_dir=self.art_dir, root=self.tmp)
        self.assertEqual(report["verdict"], "FAIL")
        bad_result = next(r for r in report["bead_results"] if r["bead_id"] == "bd-badjson")
        self.assertEqual(bad_result["verdict"], "FAIL")
        self.assertIn("invalid JSON", bad_result["detail"])


class TestKeyArtifactChecks(unittest.TestCase):
    def setUp(self):
        self.checker = load_checker()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.art_dir = self.tmp / "artifacts" / "section_bootstrap"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_missing_key_artifact_fails(self):
        """Gate fails when a key artifact is missing, even if all beads pass."""
        _write_evidence(self.art_dir / "bd-ok", "bd-ok", "PASS")
        # Only create one of the two key artifacts.
        first_artifact = self.tmp / self.checker.KEY_ARTIFACTS[0]
        first_artifact.parent.mkdir(parents=True, exist_ok=True)
        first_artifact.write_text("stub", encoding="utf-8")
        # Deliberately skip the second key artifact.

        report = self.checker.run_checks(artifacts_dir=self.art_dir, root=self.tmp)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertFalse(report["summary"]["key_artifacts_present"])
        self.assertEqual(report["summary"]["dimensions"]["docs_validation"], "FAIL")


class TestSelfExclusion(unittest.TestCase):
    def setUp(self):
        self.checker = load_checker()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.art_dir = self.tmp / "artifacts" / "section_bootstrap"

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_self_bead_excluded(self):
        """The gate's own bead (bd-3ohj) is excluded from discovery."""
        _write_evidence(self.art_dir / "bd-aaa", "bd-aaa", "PASS")
        _write_evidence(self.art_dir / "bd-3ohj", "bd-3ohj", "PASS")
        _create_key_artifacts(self.tmp, self.checker)

        report = self.checker.run_checks(artifacts_dir=self.art_dir, root=self.tmp)
        discovered_ids = [r["bead_id"] for r in report["bead_results"]]
        self.assertNotIn("bd-3ohj", discovered_ids)
        self.assertEqual(report["summary"]["beads_discovered"], 1)


if __name__ == "__main__":
    unittest.main()
