"""Unit tests for scripts/check_fork_detection.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_fork_detection as mod


class TestConstants(unittest.TestCase):
    def test_required_types_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TYPES), 12)

    def test_required_methods_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_METHODS), 15)

    def test_event_codes_count(self):
        self.assertEqual(len(mod.EVENT_CODES), 8)

    def test_invariants_count(self):
        self.assertEqual(len(mod.INVARIANTS), 4)

    def test_response_modes_count(self):
        self.assertEqual(len(mod.RESPONSE_MODES), 4)

    def test_gate_states_count(self):
        self.assertEqual(len(mod.GATE_STATES), 5)

    def test_mutation_kinds_count(self):
        self.assertEqual(len(mod.MUTATION_KINDS), 6)

    def test_required_tests_count(self):
        self.assertGreaterEqual(len(mod.REQUIRED_TESTS), 40)


class TestCheckFiles(unittest.TestCase):
    def test_all_files_exist(self):
        results = mod.check_files()
        for r in results:
            self.assertTrue(r["pass"], f"File missing: {r['check']}")

    def test_file_count(self):
        results = mod.check_files()
        self.assertEqual(len(results), 6)


class TestCheckModule(unittest.TestCase):
    def test_module_registered(self):
        result = mod.check_module_registered()
        self.assertTrue(result["pass"])


class TestCheckTypes(unittest.TestCase):
    def test_all_types_found(self):
        results = mod.check_types()
        for r in results:
            self.assertTrue(r["pass"], f"Type missing: {r['check']}")


class TestCheckMethods(unittest.TestCase):
    def test_all_methods_found(self):
        results = mod.check_methods()
        for r in results:
            self.assertTrue(r["pass"], f"Method missing: {r['check']}")


class TestCheckEventCodes(unittest.TestCase):
    def test_all_event_codes_found(self):
        results = mod.check_event_codes()
        for r in results:
            self.assertTrue(r["pass"], f"Event code missing: {r['check']}")


class TestCheckInvariants(unittest.TestCase):
    def test_all_invariants_found(self):
        results = mod.check_invariants()
        for r in results:
            self.assertTrue(r["pass"], f"Invariant missing: {r['check']}")


class TestCheckResponseModes(unittest.TestCase):
    def test_all_modes_found(self):
        results = mod.check_response_modes()
        for r in results:
            self.assertTrue(r["pass"], f"Response mode missing: {r['check']}")


class TestCheckGateStates(unittest.TestCase):
    def test_all_states_found(self):
        results = mod.check_gate_states()
        for r in results:
            self.assertTrue(r["pass"], f"Gate state missing: {r['check']}")


class TestCheckMutationKinds(unittest.TestCase):
    def test_all_kinds_found(self):
        results = mod.check_mutation_kinds()
        for r in results:
            self.assertTrue(r["pass"], f"Mutation kind missing: {r['check']}")


class TestCheckTests(unittest.TestCase):
    def test_all_tests_found(self):
        results = mod.check_tests()
        for r in results:
            self.assertTrue(r["pass"], f"Test missing: {r['check']}")


class TestCheckTestCount(unittest.TestCase):
    def test_sufficient_tests(self):
        result = mod.check_test_count()
        self.assertTrue(result["pass"], result["detail"])


class TestCheckUpstream(unittest.TestCase):
    def test_all_upstream_patterns(self):
        results = mod.check_upstream_integration()
        for r in results:
            self.assertTrue(r["pass"], f"Upstream pattern missing: {r['check']}")


class TestCheckSerde(unittest.TestCase):
    def test_serde_derives(self):
        result = mod.check_serde_derives()
        self.assertTrue(result["pass"])


class TestCheckSha256(unittest.TestCase):
    def test_sha256_usage(self):
        result = mod.check_sha256_usage()
        self.assertTrue(result["pass"])


class TestCheckSpec(unittest.TestCase):
    def test_spec_sections(self):
        results = mod.check_spec_sections()
        for r in results:
            self.assertTrue(r["pass"], f"Spec section missing: {r['check']}")


class TestRunChecks(unittest.TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"], self._failing(result))

    def test_verdict_pass(self):
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS", self._failing(result))

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-2ms")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.10")

    def test_zero_failing(self):
        result = mod.run_checks()
        self.assertEqual(result["summary"]["failing"], 0, self._failing(result))

    def test_many_checks(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["summary"]["total"], 100)

    def _failing(self, result):
        failures = [c for c in result["checks"] if not c["pass"]]
        return "\n".join(f"  FAIL: {c['check']}: {c['detail']}" for c in failures[:10])


class TestSelfTest(unittest.TestCase):
    def test_passes(self):
        ok, msg = mod.self_test()
        self.assertTrue(ok, msg)


class TestJsonOutput(unittest.TestCase):
    def test_serializable(self):
        result = mod.run_checks()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-2ms")

    def test_all_fields(self):
        result = mod.run_checks()
        for key in ["bead_id", "title", "section", "overall_pass", "verdict", "summary", "checks"]:
            self.assertIn(key, result)


if __name__ == "__main__":
    unittest.main()
