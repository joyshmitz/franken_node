"""Unit tests for check_isolation_backend.py verification logic."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

from scripts import check_isolation_backend

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_isolation_backend.py"
FIXTURE_PATH = ROOT / "fixtures/isolation/backend_selection_scenarios.json"
MATRIX_PATH = ROOT / "artifacts/section_10_13/bd-1vvs/strict_plus_runtime_matrix.csv"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-1vvs/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def decode_json_object(raw: str) -> dict[str, object]:
    parsed = JSON_DECODER.decode(raw)
    if not isinstance(parsed, dict):
        raise AssertionError("expected JSON object")
    return parsed


class TestIsolationFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        self.assertTrue(FIXTURE_PATH.is_file())

    def test_fixture_has_cases(self):
        data = decode_json_object(FIXTURE_PATH.read_text(encoding="utf-8"))
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_covers_all_backends(self):
        data = decode_json_object(FIXTURE_PATH.read_text(encoding="utf-8"))
        backends = set()
        for case in data["cases"]:
            if "expected_backend" in case:
                backends.add(case["expected_backend"])
        self.assertIn("microvm", backends)
        self.assertIn("hardened", backends)
        self.assertIn("os_sandbox", backends)
        self.assertIn("container", backends)

    def test_fixture_has_error_case(self):
        data = decode_json_object(FIXTURE_PATH.read_text(encoding="utf-8"))
        has_error = any("expected_error" in c for c in data["cases"])
        self.assertTrue(has_error)

    def test_fixture_cases_have_platform_info(self):
        data = decode_json_object(FIXTURE_PATH.read_text(encoding="utf-8"))
        for case in data["cases"]:
            self.assertIn("os", case)
            self.assertIn("arch", case)


class TestRuntimeMatrix(unittest.TestCase):

    def test_matrix_exists(self):
        self.assertTrue(MATRIX_PATH.is_file())

    def test_matrix_has_all_backends(self):
        content = MATRIX_PATH.read_text(encoding="utf-8")
        self.assertIn("microvm", content)
        self.assertIn("hardened", content)
        self.assertIn("os_sandbox", content)
        self.assertIn("container", content)

    def test_matrix_has_header(self):
        header = MATRIX_PATH.read_text(encoding="utf-8").splitlines()[0].strip()
        self.assertIn("os", header)
        self.assertIn("backend", header)


class TestIsolationImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = ROOT / "crates/franken-node/src/security/isolation_backend.rs"
        self.assertTrue(self.impl_path.is_file())
        self.content = self.impl_path.read_text(encoding="utf-8")

    def test_has_isolation_backend_enum(self):
        self.assertIn("enum IsolationBackend", self.content)

    def test_has_platform_capabilities(self):
        self.assertIn("struct PlatformCapabilities", self.content)

    def test_has_select_backend(self):
        self.assertIn("fn select_backend", self.content)

    def test_has_verify_policy(self):
        self.assertIn("fn verify_policy_enforcement", self.content)

    def test_has_all_backends(self):
        for b in ["MicroVm", "Hardened", "OsSandbox", "Container"]:
            self.assertIn(b, self.content, f"Missing backend {b}")

    def test_has_all_error_codes(self):
        for code in ["ISOLATION_BACKEND_UNAVAILABLE", "ISOLATION_PROBE_FAILED",
                     "ISOLATION_INIT_FAILED", "ISOLATION_POLICY_MISMATCH"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_equivalence_levels(self):
        for level in ["Full", "Equivalent", "Baseline"]:
            self.assertIn(level, self.content, f"Missing equivalence level {level}")


class TestIsolationSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = ROOT / "docs/specs/section_10_13/bd-1vvs_contract.md"
        self.assertTrue(self.spec_path.is_file())
        self.content = self.spec_path.read_text(encoding="utf-8")

    def test_has_invariants(self):
        for inv in ["INV-STRICT-PLUS-PROBE", "INV-STRICT-PLUS-EQUIVALENT",
                    "INV-STRICT-PLUS-AUDIT", "INV-STRICT-PLUS-FALLBACK"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_all_backends(self):
        for b in ["microvm", "hardened", "os_sandbox", "container"]:
            self.assertIn(b, self.content, f"Missing backend {b}")

    def test_has_error_codes(self):
        for code in ["ISOLATION_BACKEND_UNAVAILABLE", "ISOLATION_PROBE_FAILED",
                     "ISOLATION_INIT_FAILED", "ISOLATION_POLICY_MISMATCH"]:
            self.assertIn(code, self.content, f"Missing error code {code}")


class TestIsolationBackendCli(unittest.TestCase):

    def test_json_mode_requests_full_proof_by_default(self):
        args = check_isolation_backend.parse_args(["--json"])

        self.assertTrue(check_isolation_backend.should_run_rust_tests(args))

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

        self.assertEqual(evidence["gate"], "isolation_backend_verification")
        self.assertEqual(evidence["mode"], "structural")
        self.assertEqual(evidence["verdict"], "PARTIAL")
        self.assertEqual(statuses["ISOL-TESTS"], "SKIP")
        self.assertEqual(evidence["summary"]["skipped_checks"], 1)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("bd-1vvs:", result.stdout)

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
