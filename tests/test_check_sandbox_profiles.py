"""Unit tests for check_sandbox_profiles.py verification logic."""

import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestSandboxFixtures(unittest.TestCase):

    def _load_fixture(self, name):
        path = os.path.join(ROOT, "fixtures/sandbox_profiles", name)
        self.assertTrue(os.path.isfile(path), f"Fixture {name} must exist")
        with open(path) as f:
            return json.load(f)

    def test_profile_capabilities_exist(self):
        data = self._load_fixture("profile_capabilities.json")
        self.assertIn("profiles", data)

    def test_downgrade_scenarios_exist(self):
        data = self._load_fixture("downgrade_scenarios.json")
        self.assertIn("cases", data)
        self.assertGreater(len(data["cases"]), 0)

    def test_all_four_profiles_in_capabilities(self):
        data = self._load_fixture("profile_capabilities.json")
        for p in ["strict", "strict_plus", "moderate", "permissive"]:
            self.assertIn(p, data["profiles"], f"Missing profile {p}")

    def test_each_profile_has_6_grants(self):
        data = self._load_fixture("profile_capabilities.json")
        for p, info in data["profiles"].items():
            self.assertEqual(len(info["grants"]), 6, f"Profile {p} should have 6 grants")

    def test_strict_all_deny(self):
        data = self._load_fixture("profile_capabilities.json")
        for cap, access in data["profiles"]["strict"]["grants"].items():
            self.assertEqual(access, "deny", f"strict.{cap} should be deny")

    def test_permissive_all_allow(self):
        data = self._load_fixture("profile_capabilities.json")
        for cap, access in data["profiles"]["permissive"]["grants"].items():
            self.assertEqual(access, "allow", f"permissive.{cap} should be allow")

    def test_downgrade_has_blocked_and_ok_cases(self):
        data = self._load_fixture("downgrade_scenarios.json")
        results = [c["expected"] for c in data["cases"]]
        self.assertIn("ok", results)
        self.assertIn("SANDBOX_DOWNGRADE_BLOCKED", results)

    def test_levels_ascending(self):
        data = self._load_fixture("profile_capabilities.json")
        levels = [data["profiles"][p]["level"] for p in ["strict", "strict_plus", "moderate", "permissive"]]
        for i in range(1, len(levels)):
            self.assertGreater(levels[i], levels[i - 1])


class TestSandboxCompilerOutput(unittest.TestCase):

    def test_compiler_output_exists(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3ua7/sandbox_profile_compiler_output.json")
        self.assertTrue(os.path.isfile(path))

    def test_compiler_output_has_4_policies(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3ua7/sandbox_profile_compiler_output.json")
        with open(path) as f:
            data = json.load(f)
        self.assertEqual(len(data["compiled_policies"]), 4)

    def test_each_policy_has_6_grants(self):
        path = os.path.join(ROOT, "artifacts/section_10_13/bd-3ua7/sandbox_profile_compiler_output.json")
        with open(path) as f:
            data = json.load(f)
        for p in data["compiled_policies"]:
            self.assertEqual(len(p["grants"]), 6, f"Policy {p['profile']} should have 6 grants")


class TestSandboxImplementation(unittest.TestCase):

    def setUp(self):
        self.impl_path = os.path.join(ROOT, "crates/franken-node/src/security/sandbox_policy_compiler.rs")
        self.assertTrue(os.path.isfile(self.impl_path))
        with open(self.impl_path) as f:
            self.content = f.read()

    def test_has_sandbox_profile_enum(self):
        self.assertIn("enum SandboxProfile", self.content)

    def test_has_compile_policy(self):
        self.assertIn("fn compile_policy", self.content)

    def test_has_profile_tracker(self):
        self.assertIn("struct ProfileTracker", self.content)

    def test_has_downgrade_check(self):
        self.assertIn("is_downgrade_to", self.content)

    def test_has_all_error_codes(self):
        for code in ["SANDBOX_DOWNGRADE_BLOCKED", "SANDBOX_PROFILE_UNKNOWN",
                     "SANDBOX_POLICY_CONFLICT", "SANDBOX_COMPILE_ERROR"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_access_levels(self):
        for level in ["Deny", "Scoped", "Filtered", "Allow"]:
            self.assertIn(level, self.content, f"Missing access level {level}")


class TestSandboxSpec(unittest.TestCase):

    def setUp(self):
        self.spec_path = os.path.join(ROOT, "docs/specs/section_10_13/bd-3ua7_contract.md")
        self.assertTrue(os.path.isfile(self.spec_path))
        with open(self.spec_path) as f:
            self.content = f.read()

    def test_has_invariants(self):
        for inv in ["INV-SANDBOX-TIERED", "INV-SANDBOX-NO-DOWNGRADE",
                    "INV-SANDBOX-COMPILED", "INV-SANDBOX-AUDIT"]:
            self.assertIn(inv, self.content, f"Missing invariant {inv}")

    def test_has_error_codes(self):
        for code in ["SANDBOX_DOWNGRADE_BLOCKED", "SANDBOX_PROFILE_UNKNOWN",
                     "SANDBOX_POLICY_CONFLICT", "SANDBOX_COMPILE_ERROR"]:
            self.assertIn(code, self.content, f"Missing error code {code}")

    def test_has_all_profiles(self):
        for p in ["strict", "strict_plus", "moderate", "permissive"]:
            self.assertIn(p, self.content, f"Missing profile {p}")


if __name__ == "__main__":
    unittest.main()
