"""Unit tests for scripts/check_bpet_governance.py."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_bpet_governance as mod


class TestConstants(unittest.TestCase):
    def test_required_event_codes(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 6)
        self.assertIn("BPET-GOV-001", mod.REQUIRED_EVENT_CODES)
        self.assertIn("BPET-GOV-007", mod.REQUIRED_EVENT_CODES)

    def test_policy_headings(self):
        self.assertGreaterEqual(len(mod.POLICY_HEADINGS), 7)


class TestHelpers(unittest.TestCase):
    def test_read_jsonl_has_entries(self):
        entries = mod._read_jsonl(mod.AUDIT_LOG)
        self.assertGreaterEqual(len(entries), 6)

    def test_entries_are_dicts(self):
        entries = mod._read_jsonl(mod.AUDIT_LOG)
        self.assertTrue(all(isinstance(e, dict) for e in entries))


class TestRunAllChecks(unittest.TestCase):
    def test_returns_list(self):
        checks = mod.run_all_checks()
        self.assertIsInstance(checks, list)

    def test_required_keys_present(self):
        for check in mod.run_all_checks():
            self.assertIn("check", check)
            self.assertIn("pass", check)
            self.assertIn("detail", check)

    def test_all_checks_pass(self):
        checks = mod.run_all_checks()
        failing = [c for c in checks if not c["pass"]]
        self.assertEqual(len(failing), 0, "\n".join(f"FAIL: {c['check']} :: {c['detail']}" for c in failing))

    def test_has_enough_checks(self):
        checks = mod.run_all_checks()
        self.assertGreaterEqual(len(checks), 12)


class TestRunAll(unittest.TestCase):
    def test_output_shape(self):
        result = mod.run_all()
        for key in [
            "bead_id",
            "title",
            "section",
            "verdict",
            "overall_pass",
            "total",
            "passed",
            "failed",
            "checks",
            "artifacts",
        ]:
            self.assertIn(key, result)

    def test_identity(self):
        result = mod.run_all()
        self.assertEqual(result["bead_id"], "bd-1naf")
        self.assertEqual(result["section"], "10.21")

    def test_verdict_pass(self):
        result = mod.run_all()
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["overall_pass"])
        self.assertEqual(result["failed"], 0)

    def test_json_serializable(self):
        result = mod.run_all()
        parsed = json.loads(json.dumps(result))
        self.assertEqual(parsed["bead_id"], "bd-1naf")


class TestKeyChecks(unittest.TestCase):
    def test_policy_and_audit_checks_present(self):
        checks = {c["check"]: c for c in mod.run_all_checks()}
        for name in [
            "policy_sections",
            "policy_event_codes",
            "policy_hard_stop_clause",
            "audit_entries_present",
            "audit_schema",
            "audit_event_code_coverage",
            "audit_appeal_lifecycle",
            "audit_override_signature",
            "audit_override_bounds",
        ]:
            self.assertIn(name, checks)
            self.assertTrue(checks[name]["pass"], f"{name}: {checks[name]['detail']}")


class TestSelfTest(unittest.TestCase):
    def test_self_test(self):
        self.assertTrue(mod.self_test())


if __name__ == "__main__":
    unittest.main()
