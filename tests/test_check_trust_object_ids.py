"""Unit tests for scripts/check_trust_object_ids.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_trust_object_ids as mod


class TestConstants(unittest.TestCase):
    def test_required_structs_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_STRUCTS), 7)

    def test_required_event_codes_count(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 2)

    def test_required_error_codes_count(self):
        self.assertEqual(len(mod.REQUIRED_ERROR_CODES), 4)

    def test_required_invariants_count(self):
        self.assertEqual(len(mod.REQUIRED_INVARIANTS), 4)

    def test_required_functions_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_FUNCTIONS), 12)

    def test_domain_prefixes_count(self):
        self.assertEqual(len(mod.DOMAIN_PREFIXES), 6)

    def test_derivation_modes_count(self):
        self.assertEqual(len(mod.DERIVATION_MODES), 2)

    def test_required_spec_sections_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_SPEC_SECTIONS), 9)


class TestSimulation(unittest.TestCase):
    def test_deterministic(self):
        result = mod.simulate_trust_object_ids()
        self.assertTrue(result["deterministic"])

    def test_different_inputs(self):
        result = mod.simulate_trust_object_ids()
        self.assertTrue(result["different_inputs_different"])

    def test_cross_domain_unique(self):
        result = mod.simulate_trust_object_ids()
        self.assertTrue(result["cross_domain_unique"])

    def test_short_form_length(self):
        result = mod.simulate_trust_object_ids()
        self.assertEqual(result["short_form_length"], 8)

    def test_context_addressed(self):
        result = mod.simulate_trust_object_ids()
        self.assertTrue(result["context_addressed_works"])

    def test_digest_256_bits(self):
        result = mod.simulate_trust_object_ids()
        self.assertTrue(result["digest_length_256_bits"])

    def test_hex_digest(self):
        result = mod.simulate_trust_object_ids()
        self.assertTrue(result["digest_is_hex"])

    def test_domain_prefix_count(self):
        result = mod.simulate_trust_object_ids()
        self.assertEqual(result["domain_prefix_count"], 6)

    def test_derivation_mode_count(self):
        result = mod.simulate_trust_object_ids()
        self.assertEqual(result["derivation_mode_count"], 2)


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-1l5")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.10")

    def test_zero_failing(self):
        result = mod.run_checks()
        self.assertEqual(result["failed"], 0, self._failing(result))

    def test_many_checks(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["total"], 80)

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["pass"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestRunAll(unittest.TestCase):
    def test_run_all_alias(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-1l5")
        self.assertIn("verdict", result)


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok, f"self_test failed with {sum(1 for c in checks if not c['pass'])} failures")


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        result = mod.run_checks()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-1l5")

    def test_all_fields(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "verdict", "total", "passed", "failed", "checks"]:
            self.assertIn(key, result)


class TestHelpers(unittest.TestCase):
    def test_sha256_deterministic(self):
        h1 = mod._sha256_hex(b"test data")
        h2 = mod._sha256_hex(b"test data")
        self.assertEqual(h1, h2)

    def test_sha256_distinct(self):
        h1 = mod._sha256_hex(b"data-a")
        h2 = mod._sha256_hex(b"data-b")
        self.assertNotEqual(h1, h2)

    def test_sha256_length(self):
        h = mod._sha256_hex(b"test")
        self.assertEqual(len(h), 64)


class TestFileChecks(unittest.TestCase):
    def test_impl_exists(self):
        result = mod.run_checks()
        impl_check = next(
            c for c in result["checks"] if "trust_object_id implementation" in c["check"]
        )
        self.assertTrue(impl_check["pass"])

    def test_spec_exists(self):
        result = mod.run_checks()
        spec_check = next(c for c in result["checks"] if "contract spec" in c["check"])
        self.assertTrue(spec_check["pass"])


if __name__ == "__main__":
    unittest.main()
