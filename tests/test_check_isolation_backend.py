"""Unit tests for check_isolation_backend.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestIsolationFixtures(unittest.TestCase):

    def test_fixture_exists(self):
        path = os.path.join(ROOT, "fixtures/isolation/backend_selection_scenarios.json")
        self.assertTrue(os.path.isfile(path))

    def test_fixture_has_cases(self):
        path = os.path.join(ROOT, "fixtures/isolation/backend_selection_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        self.assertIn("cases", data)
        self.assertGreaterEqual(len(data["cases"]), 4)

    def test_fixture_covers_all_backends(self):
        path = os.path.join(ROOT, "fixtures/isolation/backend_selection_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        backends = set()
        for case in data["cases"]:
            if "expected_backend" in case:
                backends.add(case["expected_backend"])
        self.assertIn("microvm", backends)
        self.assertIn("hardened", backends)
        self.assertIn("os_sandbox", backends)
        self.assertIn("container", backends)

    def test_fixture_has_error_case(self):
        path = os.path.join(ROOT, "fixtures/isolation/backend_selection_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        has_error = any("expected_error" in c for c in data["cases"])
        self.assertTrue(has_error)

    def test_fixture_cases_have_platform_info(self):
        path = os.path.join(ROOT, "fixtures/isolation/backend_selection_scenarios.json")
        with open(path) as f:
            data = json.load(f)
        for case in data["cases"]:
            self.assertIn("os", case)
            self.assertIn("arch", case)


class TestRuntimeMatrix(unittest.TestCase):

    def test_matrix_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1vvs/strict_plus_runtime_matrix.csv")
        self.assertTrue(os.path.isfile(path))

    def test_matrix_has_all_backends(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1vvs/strict_plus_runtime_matrix.csv")
        with open(path) as f:
            content = f.read()
        self.assertIn("microvm", content)
        self.assertIn("hardened", content)
        self.assertIn("os_sandbox", content)
        self.assertIn("container", content)

    def test_matrix_has_header(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-1vvs/strict_plus_runtime_matrix.csv")
        with open(path) as f:
            header = f.readline().strip()
        self.assertIn("os", header)
        self.assertIn("backend", header)


class TestIsolationImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/security/isolation_backend.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

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
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-1vvs_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

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


if __name__ == "__main__":
    unittest.main()
