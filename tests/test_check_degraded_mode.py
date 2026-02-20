"""Unit tests for scripts/check_degraded_mode.py."""

import importlib.util
import sys
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_degraded_mode",
    ROOT / "scripts" / "check_degraded_mode.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class TestFixture(TestCase):
    def test_impl_exists(self):
        self.assertTrue(mod.IMPL.is_file())

    def test_contract_exists(self):
        self.assertTrue(mod.SPEC.is_file())


class TestTriggerVariants(TestCase):
    def test_health_gate_failed_trigger(self):
        sim = mod.simulate_mode_lifecycle("health_gate_failed:revocation_frontier")
        self.assertEqual(sim["state"]["events"][1]["event_code"], "DEGRADED_MODE_ENTERED")

    def test_capability_unavailable_trigger(self):
        sim = mod.simulate_mode_lifecycle("capability_unavailable:federation_peer")
        self.assertEqual(sim["state"]["events"][1]["event_code"], "DEGRADED_MODE_ENTERED")

    def test_error_rate_exceeded_trigger(self):
        sim = mod.simulate_mode_lifecycle("error_rate_exceeded:0.1500:60")
        self.assertEqual(sim["state"]["events"][1]["event_code"], "DEGRADED_MODE_ENTERED")

    def test_manual_activation_trigger(self):
        sim = mod.simulate_mode_lifecycle("manual_activation:operator-1")
        self.assertEqual(sim["state"]["events"][1]["event_code"], "DEGRADED_MODE_ENTERED")

    def test_unconfigured_trigger_rejected(self):
        policy = mod.base_policy()
        state = mod.make_state()
        with self.assertRaises(ValueError):
            mod.activate(
                policy,
                state,
                "health_gate_failed:unknown",
                1000,
                "1.0.0",
                "trace-x",
            )


class TestBehaviorPaths(TestCase):
    def setUp(self):
        self.sim = mod.simulate_mode_lifecycle("health_gate_failed:revocation_frontier")
        self.events = self.sim["state"]["events"]
        self.codes = [event["event_code"] for event in self.events]

    def test_denied_action_path(self):
        denied = self.sim["denied_decision"]
        self.assertFalse(denied["permitted"])
        self.assertEqual(denied["denial_reason"], "denied_actions.policy.change")
        self.assertIn("DEGRADED_ACTION_BLOCKED", self.codes)

    def test_missed_audit_alert(self):
        self.assertIn("AUDIT_EVENT_MISSED", self.codes)

    def test_stabilization_window_exit(self):
        self.assertEqual(self.sim["state"]["mode"], "normal")
        self.assertIn("DEGRADED_MODE_EXITED", self.codes)

    def test_event_ordering(self):
        entered_idx = self.codes.index("DEGRADED_MODE_ENTERED")
        blocked_idx = self.codes.index("DEGRADED_ACTION_BLOCKED")
        exited_idx = self.codes.index("DEGRADED_MODE_EXITED")
        self.assertLess(entered_idx, blocked_idx)
        self.assertLess(blocked_idx, exited_idx)

    def test_suspend_path_blocks_non_essential(self):
        policy = mod.base_policy()
        state = mod.make_state()
        mod.activate(
            policy,
            state,
            "health_gate_failed:revocation_frontier",
            1000,
            "1.0.0",
            "trace-suspend",
        )
        mod.maybe_suspend(policy, state, 1120, "trace-suspend")
        blocked = mod.evaluate_action(
            policy,
            state,
            "policy.change",
            "alice",
            1121,
            "trace-suspend",
        )
        allowed = mod.evaluate_action(
            policy,
            state,
            "health.check",
            "alice",
            1122,
            "trace-suspend",
        )
        self.assertFalse(blocked["permitted"])
        self.assertTrue(allowed["permitted"])


class TestChecks(TestCase):
    def test_run_checks_passes(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-3nr")
        self.assertEqual(result["verdict"], "PASS")

    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreater(len(checks), 0)


if __name__ == "__main__":
    main()
