"""Unit tests for scripts/check_vef_claim_integration.py (bd-3go4)."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "check_vef_claim_integration",
    ROOT / "scripts" / "check_vef_claim_integration.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# Core self_test
# ---------------------------------------------------------------------------


class TestSelfTest(unittest.TestCase):
    """self_test() returns bool and does not raise."""

    def test_self_test(self) -> None:
        result = mod.self_test()
        self.assertIsInstance(result, bool)

    def test_self_test_consistent_with_run_all(self) -> None:
        report = mod.run_all()
        expected = report["failed"] == 0
        result = mod.self_test()
        self.assertEqual(result, expected)


# ---------------------------------------------------------------------------
# Snapshot validation
# ---------------------------------------------------------------------------


class TestValidSnapshotPasses(unittest.TestCase):
    """A well-formed snapshot with sufficient coverage passes all snapshot checks."""

    def setUp(self) -> None:
        mod.RESULTS = []
        self._orig_snapshot = mod.SNAPSHOT
        self._tmpdir = tempfile.mkdtemp()
        self._snapshot_path = Path(self._tmpdir) / "snapshot.json"
        snapshot = {
            "schema_version": "vef-claim-v1.0",
            "bead_id": "bd-3go4",
            "section": "10.18",
            "timestamp": "2026-02-22T00:00:00Z",
            "coverage": {
                "total_action_classes": 12,
                "covered_action_classes": 12,
                "coverage_percentage": 100.0,
                "coverage_gaps": [],
            },
            "validity": {
                "total_proofs_checked": 48,
                "valid_proofs": 48,
                "verification_success_rate": 100.0,
                "degraded_mode_fraction": 0.0,
            },
            "claim_gate_results": [
                {
                    "claim_id": "trust-integrity",
                    "required_coverage": 80.0,
                    "actual_coverage": 100.0,
                    "verdict": "PASS",
                },
                {
                    "claim_id": "replay-determinism",
                    "required_coverage": 90.0,
                    "actual_coverage": 100.0,
                    "verdict": "PASS",
                },
                {
                    "claim_id": "safety-no-ambient-authority",
                    "required_coverage": 95.0,
                    "actual_coverage": 100.0,
                    "verdict": "PASS",
                },
            ],
            "scoreboard_published": True,
            "verdict": "PASS",
        }
        self._snapshot_path.write_text(json.dumps(snapshot, indent=2))
        mod.SNAPSHOT = self._snapshot_path

    def tearDown(self) -> None:
        mod.SNAPSHOT = self._orig_snapshot
        mod.RESULTS = []
        if self._snapshot_path.exists():
            self._snapshot_path.unlink()
        os.rmdir(self._tmpdir)

    def test_valid_snapshot_passes(self) -> None:
        mod.check_snapshot_exists()
        mod.check_snapshot_valid_json()
        mod.check_snapshot_bead_id()
        mod.check_snapshot_coverage()
        mod.check_snapshot_claim_gates()
        mod.check_snapshot_verdict()
        for r in mod.RESULTS:
            self.assertTrue(r["pass"], f"{r['check']} should pass: {r['detail']}")


class TestLowCoverageFails(unittest.TestCase):
    """A snapshot with coverage below threshold fails the coverage check."""

    def setUp(self) -> None:
        mod.RESULTS = []
        self._orig_snapshot = mod.SNAPSHOT
        self._tmpdir = tempfile.mkdtemp()
        self._snapshot_path = Path(self._tmpdir) / "snapshot.json"
        snapshot = {
            "schema_version": "vef-claim-v1.0",
            "bead_id": "bd-3go4",
            "section": "10.18",
            "timestamp": "2026-02-22T00:00:00Z",
            "coverage": {
                "total_action_classes": 12,
                "covered_action_classes": 6,
                "coverage_percentage": 50.0,
                "coverage_gaps": [
                    "transfer-ownership",
                    "publish-attestation",
                    "register-verifier",
                    "file-dispute",
                    "resolve-dispute",
                    "update-reputation",
                ],
            },
            "validity": {
                "total_proofs_checked": 24,
                "valid_proofs": 24,
                "verification_success_rate": 100.0,
                "degraded_mode_fraction": 0.0,
            },
            "claim_gate_results": [
                {
                    "claim_id": "trust-integrity",
                    "required_coverage": 80.0,
                    "actual_coverage": 50.0,
                    "verdict": "FAIL",
                }
            ],
            "scoreboard_published": True,
            "verdict": "FAIL",
        }
        self._snapshot_path.write_text(json.dumps(snapshot, indent=2))
        mod.SNAPSHOT = self._snapshot_path

    def tearDown(self) -> None:
        mod.SNAPSHOT = self._orig_snapshot
        mod.RESULTS = []
        if self._snapshot_path.exists():
            self._snapshot_path.unlink()
        os.rmdir(self._tmpdir)

    def test_low_coverage_fails(self) -> None:
        mod.check_snapshot_coverage()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(
            mod.RESULTS[0]["pass"],
            "coverage 50% should fail against 80% threshold",
        )
        self.assertIn("50.0", mod.RESULTS[0]["detail"])

    def test_claim_gate_failure(self) -> None:
        mod.check_snapshot_claim_gates()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(
            mod.RESULTS[0]["pass"],
            "claim gate with FAIL verdict should fail check",
        )

    def test_verdict_failure(self) -> None:
        mod.check_snapshot_verdict()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(
            mod.RESULTS[0]["pass"],
            "snapshot verdict FAIL should fail check",
        )


# ---------------------------------------------------------------------------
# run_all structure
# ---------------------------------------------------------------------------


class TestRunAllStructure(unittest.TestCase):
    """run_all() returns a well-formed result dict."""

    def test_returns_dict(self) -> None:
        result = mod.run_all()
        self.assertIsInstance(result, dict)

    def test_bead_id(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-3go4")

    def test_section(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["section"], "10.18")

    def test_title(self) -> None:
        result = mod.run_all()
        self.assertEqual(
            result["title"],
            "VEF coverage and proof-validity metrics integration",
        )

    def test_verdict_is_string(self) -> None:
        result = mod.run_all()
        self.assertIn(result["verdict"], ("PASS", "FAIL"))

    def test_total_positive(self) -> None:
        result = mod.run_all()
        self.assertGreater(result["total"], 0)

    def test_passed_lte_total(self) -> None:
        result = mod.run_all()
        self.assertLessEqual(result["passed"], result["total"])

    def test_failed_consistency(self) -> None:
        result = mod.run_all()
        self.assertEqual(result["failed"], result["total"] - result["passed"])

    def test_checks_is_list(self) -> None:
        result = mod.run_all()
        self.assertIsInstance(result["checks"], list)
        self.assertEqual(len(result["checks"]), result["total"])

    def test_verdict_consistency(self) -> None:
        result = mod.run_all()
        if result["failed"] == 0:
            self.assertEqual(result["verdict"], "PASS")
        else:
            self.assertEqual(result["verdict"], "FAIL")

    def test_check_names_unique(self) -> None:
        result = mod.run_all()
        names = [c["check"] for c in result["checks"]]
        self.assertEqual(len(names), len(set(names)), "Duplicate check names found")

    def test_check_entry_format(self) -> None:
        result = mod.run_all()
        for c in result["checks"]:
            self.assertIn("check", c)
            self.assertIn("pass", c)
            self.assertIn("detail", c)
            self.assertIsInstance(c["check"], str)
            self.assertIsInstance(c["pass"], bool)
            self.assertIsInstance(c["detail"], str)


# ---------------------------------------------------------------------------
# Missing file detection
# ---------------------------------------------------------------------------


class TestMissingFileDetection(unittest.TestCase):
    """Checks correctly report missing files."""

    def setUp(self) -> None:
        mod.RESULTS = []
        self._orig_spec = mod.SPEC
        self._orig_snapshot = mod.SNAPSHOT
        self._orig_evidence = mod.EVIDENCE
        self._orig_conformance = mod.CONFORMANCE
        self._orig_impl = mod.IMPL

    def tearDown(self) -> None:
        mod.SPEC = self._orig_spec
        mod.SNAPSHOT = self._orig_snapshot
        mod.EVIDENCE = self._orig_evidence
        mod.CONFORMANCE = self._orig_conformance
        mod.IMPL = self._orig_impl
        mod.RESULTS = []

    def test_missing_spec_detected(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_exists()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])
        self.assertIn("MISSING", mod.RESULTS[0]["detail"])

    def test_missing_snapshot_detected(self) -> None:
        mod.SNAPSHOT = Path("/nonexistent/snapshot.json")
        mod.check_snapshot_exists()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])
        self.assertIn("MISSING", mod.RESULTS[0]["detail"])

    def test_missing_evidence_detected(self) -> None:
        mod.EVIDENCE = Path("/nonexistent/evidence.json")
        mod.check_evidence_exists()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])
        self.assertIn("MISSING", mod.RESULTS[0]["detail"])

    def test_missing_conformance_detected(self) -> None:
        mod.CONFORMANCE = Path("/nonexistent/conformance.rs")
        mod.check_conformance_exists()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])
        self.assertIn("MISSING", mod.RESULTS[0]["detail"])

    def test_missing_impl_detected(self) -> None:
        mod.IMPL = Path("/nonexistent/impl.rs")
        mod.check_impl_exists()
        self.assertEqual(len(mod.RESULTS), 1)
        self.assertFalse(mod.RESULTS[0]["pass"])
        self.assertIn("MISSING", mod.RESULTS[0]["detail"])

    def test_missing_spec_bead_id(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_bead_id()
        self.assertFalse(mod.RESULTS[0]["pass"])
        self.assertIn("spec file missing", mod.RESULTS[0]["detail"])

    def test_missing_spec_event_codes(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_event_codes()
        self.assertEqual(len(mod.RESULTS), 4)
        for r in mod.RESULTS:
            self.assertFalse(r["pass"])

    def test_missing_spec_invariants(self) -> None:
        mod.SPEC = Path("/nonexistent/spec.md")
        mod.check_spec_invariants()
        self.assertEqual(len(mod.RESULTS), 4)
        for r in mod.RESULTS:
            self.assertFalse(r["pass"])

    def test_missing_impl_event_codes(self) -> None:
        mod.IMPL = Path("/nonexistent/impl.rs")
        mod.check_impl_event_codes()
        self.assertEqual(len(mod.RESULTS), 4)
        for r in mod.RESULTS:
            self.assertFalse(r["pass"])

    def test_missing_impl_invariants(self) -> None:
        mod.IMPL = Path("/nonexistent/impl.rs")
        mod.check_impl_invariants()
        self.assertEqual(len(mod.RESULTS), 4)
        for r in mod.RESULTS:
            self.assertFalse(r["pass"])


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


class TestJsonOutput(unittest.TestCase):
    """--json flag produces valid JSON."""

    def test_json_serializable(self) -> None:
        result = mod.run_all()
        output = json.dumps(result, indent=2)
        parsed = json.loads(output)
        self.assertEqual(parsed["bead_id"], "bd-3go4")
        self.assertEqual(parsed["section"], "10.18")
        self.assertIn("checks", parsed)
        self.assertIsInstance(parsed["checks"], list)

    def test_json_check_format(self) -> None:
        result = mod.run_all()
        output = json.dumps(result, indent=2)
        parsed = json.loads(output)
        for c in parsed["checks"]:
            self.assertIn("check", c)
            self.assertIn("pass", c)
            self.assertIn("detail", c)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestSafeRel(unittest.TestCase):
    """_safe_rel() handles paths correctly."""

    def test_path_within_root(self) -> None:
        p = mod.ROOT / "docs" / "specs" / "test.md"
        result = mod._safe_rel(p)
        self.assertEqual(result, "docs/specs/test.md")

    def test_path_outside_root(self) -> None:
        p = Path("/tmp/some/other/path.md")
        result = mod._safe_rel(p)
        self.assertEqual(result, "/tmp/some/other/path.md")

    def test_root_itself(self) -> None:
        result = mod._safe_rel(mod.ROOT)
        self.assertEqual(result, ".")


class TestCheckHelper(unittest.TestCase):
    """_check() helper function works correctly."""

    def setUp(self) -> None:
        mod.RESULTS = []

    def tearDown(self) -> None:
        mod.RESULTS = []

    def test_check_pass(self) -> None:
        entry = mod._check("test_pass", True, "it passed")
        self.assertEqual(entry["check"], "test_pass")
        self.assertTrue(entry["pass"])
        self.assertEqual(entry["detail"], "it passed")
        self.assertEqual(len(mod.RESULTS), 1)

    def test_check_fail(self) -> None:
        entry = mod._check("test_fail", False, "it failed")
        self.assertFalse(entry["pass"])
        self.assertEqual(entry["detail"], "it failed")

    def test_check_default_detail_pass(self) -> None:
        entry = mod._check("test_default", True)
        self.assertEqual(entry["detail"], "found")

    def test_check_default_detail_fail(self) -> None:
        entry = mod._check("test_default", False)
        self.assertEqual(entry["detail"], "NOT FOUND")

    def test_check_appends_to_results(self) -> None:
        mod._check("a", True, "ok")
        mod._check("b", False, "nope")
        self.assertEqual(len(mod.RESULTS), 2)


class TestRunAllIdempotent(unittest.TestCase):
    """run_all() resets RESULTS each time."""

    def test_idempotent(self) -> None:
        r1 = mod.run_all()
        r2 = mod.run_all()
        self.assertEqual(r1["total"], r2["total"])
        self.assertEqual(r1["passed"], r2["passed"])
        self.assertEqual(len(r1["checks"]), len(r2["checks"]))


class TestAllChecksList(unittest.TestCase):
    """Module-level ALL_CHECKS list is well-formed."""

    def test_all_checks_is_list(self) -> None:
        self.assertIsInstance(mod.ALL_CHECKS, list)
        self.assertGreater(len(mod.ALL_CHECKS), 0)
        for fn in mod.ALL_CHECKS:
            self.assertTrue(callable(fn))

    def test_root_is_directory(self) -> None:
        self.assertTrue(mod.ROOT.is_dir())


if __name__ == "__main__":
    unittest.main()
