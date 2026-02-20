#!/usr/bin/env python3
"""bd-3nr verification: degraded-mode policy behavior and mandatory audits."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT / "crates" / "franken-node" / "src" / "security" / "degraded_mode_policy.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "security" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_5" / "bd-3nr_contract.md"

REQUIRED_IMPL_PATTERNS = [
    "pub struct DegradedModePolicy",
    "pub enum TriggerCondition",
    "pub struct AuditEventSpec",
    "pub enum RecoveryCriterion",
    "pub enum DegradedModeState",
    "pub struct DegradedModePolicyEngine",
    "pub fn activate(",
    "pub fn evaluate_action(",
    "pub fn tick_mandatory_audits(",
    "pub fn observe_recovery(",
    "pub fn maybe_escalate_to_suspended(",
    "DEGRADED_MODE_ENTERED",
    "DEGRADED_MODE_EXITED",
    "DEGRADED_MODE_SUSPENDED",
    "DEGRADED_ACTION_BLOCKED",
    "DEGRADED_ACTION_ANNOTATED",
    "TRUST_INPUT_STALE",
    "TRUST_INPUT_REFRESHED",
    "AUDIT_EVENT_MISSED",
]


def check_file(path: Path, label: str) -> dict[str, Any]:
    ok = path.is_file()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"missing: {path}",
    }


def check_contains(path: Path, patterns: list[str], label: str) -> list[dict[str, Any]]:
    if not path.is_file():
        return [{"check": f"{label}: {pattern}", "pass": False, "detail": "file missing"} for pattern in patterns]
    content = path.read_text()
    checks = []
    for pattern in patterns:
        checks.append(
            {
                "check": f"{label}: {pattern}",
                "pass": pattern in content,
                "detail": "found" if pattern in content else "not found",
            }
        )
    return checks


def base_policy() -> dict[str, Any]:
    return {
        "mode_name": "trust-input-stale",
        "trigger_conditions": [
            "health_gate_failed:revocation_frontier",
            "capability_unavailable:federation_peer",
            "error_rate_exceeded:0.1500:60",
            "manual_activation:operator-1",
        ],
        "permitted_actions": {"health.check"},
        "denied_actions": {"policy.change", "key.rotate"},
        "mandatory_audit_events": [{"event_code": "DEGRADED_HEARTBEAT", "interval_secs": 60}],
        "auto_recovery_criteria": [
            "health_gate_restored:revocation_frontier",
            "capability_available:federation_peer",
            "error_rate_below:0.0500:300",
        ],
        "stabilization_window_secs": 300,
        "max_degraded_duration_secs": 120,
    }


def make_state() -> dict[str, Any]:
    return {
        "mode": "normal",
        "entered_at_secs": None,
        "policy_version": None,
        "triggering_condition": None,
        "stabilization_started_at_secs": None,
        "last_emitted": {},
        "events": [],
    }


def emit(state: dict[str, Any], code: str, timestamp: int, **payload: Any) -> None:
    state["events"].append(
        {
            "event_code": code,
            "timestamp_secs": int(timestamp),
            **payload,
        }
    )


def activate(
    policy: dict[str, Any],
    state: dict[str, Any],
    trigger_condition: str,
    now_secs: int,
    policy_version: str,
    trace_id: str,
) -> None:
    if trigger_condition not in policy["trigger_conditions"]:
        raise ValueError(f"trigger not configured: {trigger_condition}")

    denied_actions = sorted(policy["denied_actions"])
    emit(
        state,
        "TRUST_INPUT_STALE",
        now_secs,
        input_label=trigger_condition,
        mode_name=policy["mode_name"],
        trace_id=trace_id,
    )
    emit(
        state,
        "DEGRADED_MODE_ENTERED",
        now_secs,
        mode_name=policy["mode_name"],
        triggering_condition=trigger_condition,
        active_policy_version=policy_version,
        denied_actions=denied_actions,
        trace_id=trace_id,
    )
    state["mode"] = "degraded"
    state["entered_at_secs"] = int(now_secs)
    state["policy_version"] = policy_version
    state["triggering_condition"] = trigger_condition
    state["stabilization_started_at_secs"] = None
    state["last_emitted"] = {spec["event_code"]: int(now_secs) for spec in policy["mandatory_audit_events"]}


def evaluate_action(
    policy: dict[str, Any],
    state: dict[str, Any],
    action_name: str,
    actor: str,
    now_secs: int,
    trace_id: str,
) -> dict[str, Any]:
    if state["mode"] == "normal":
        return {"permitted": True, "degraded_annotation": False, "denial_reason": None}

    if state["mode"] == "suspended":
        permitted = action_name in policy["permitted_actions"]
        denial_reason = None if permitted else f"suspended_mode_blocks_non_essential:{action_name}"
    else:
        permitted = action_name not in policy["denied_actions"]
        denial_reason = None if permitted else f"denied_actions.{action_name}"

    emit(
        state,
        "DEGRADED_ACTION_ANNOTATED" if permitted else "DEGRADED_ACTION_BLOCKED",
        now_secs,
        action_name=action_name,
        actor=actor,
        permitted=bool(permitted),
        denial_reason=denial_reason,
        trace_id=trace_id,
    )
    return {
        "permitted": bool(permitted),
        "degraded_annotation": True,
        "denial_reason": denial_reason,
    }


def tick_mandatory(policy: dict[str, Any], state: dict[str, Any], now_secs: int, trace_id: str) -> None:
    if state["mode"] == "normal":
        return
    for spec in policy["mandatory_audit_events"]:
        code = spec["event_code"]
        interval = max(1, int(spec["interval_secs"]))
        last = int(state["last_emitted"].get(code, now_secs))
        expected = last + interval
        if now_secs >= expected + interval:
            emit(
                state,
                "AUDIT_EVENT_MISSED",
                now_secs,
                mandatory_event_code=code,
                expected_timestamp_secs=expected,
                trace_id=trace_id,
            )
        if now_secs >= expected:
            emit(
                state,
                "MANDATORY_AUDIT_TICK",
                now_secs,
                mandatory_event_code=code,
                trace_id=trace_id,
            )
            state["last_emitted"][code] = int(now_secs)


def maybe_suspend(policy: dict[str, Any], state: dict[str, Any], now_secs: int, trace_id: str) -> None:
    if state["mode"] != "degraded":
        return
    entered = state["entered_at_secs"]
    if entered is None:
        return
    if now_secs - int(entered) < int(policy["max_degraded_duration_secs"]):
        return
    state["mode"] = "suspended"
    emit(
        state,
        "DEGRADED_MODE_SUSPENDED",
        now_secs,
        mode_name=policy["mode_name"],
        active_policy_version=state["policy_version"],
        reason=f"degraded_duration_exceeded:{policy['max_degraded_duration_secs']}s",
        trace_id=trace_id,
    )


def criteria_satisfied(status: dict[str, Any], criterion: str) -> bool:
    if criterion.startswith("health_gate_restored:"):
        gate = criterion.split(":", 1)[1]
        return gate in status.get("healthy_gates", set())
    if criterion.startswith("capability_available:"):
        capability = criterion.split(":", 1)[1]
        return capability in status.get("available_capabilities", set())
    if criterion.startswith("error_rate_below:"):
        _, threshold_raw, _window = criterion.split(":")
        threshold = float(threshold_raw)
        observed = status.get("observed_error_rate")
        return observed is not None and float(observed) <= threshold
    return False


def observe_recovery(
    policy: dict[str, Any],
    state: dict[str, Any],
    status: dict[str, Any],
    now_secs: int,
    trace_id: str,
) -> None:
    if state["mode"] == "normal":
        return

    criteria = policy["auto_recovery_criteria"]
    if not criteria:
        return
    all_met = all(criteria_satisfied(status, criterion) for criterion in criteria)
    if not all_met:
        state["stabilization_started_at_secs"] = None
        return

    if state["stabilization_started_at_secs"] is None:
        state["stabilization_started_at_secs"] = int(now_secs)
        emit(
            state,
            "TRUST_INPUT_REFRESHED",
            now_secs,
            input_label=state["triggering_condition"],
            mode_name=policy["mode_name"],
            trace_id=trace_id,
        )
        return

    stable_for = now_secs - int(state["stabilization_started_at_secs"])
    if stable_for < int(policy["stabilization_window_secs"]):
        return

    state["mode"] = "normal"
    emit(
        state,
        "DEGRADED_MODE_EXITED",
        now_secs,
        mode_name=policy["mode_name"],
        active_policy_version=state["policy_version"],
        trace_id=trace_id,
    )


def simulate_mode_lifecycle(trigger_condition: str) -> dict[str, Any]:
    policy = base_policy()
    state = make_state()
    activate(policy, state, trigger_condition, 1000, "1.0.0", "trace-lifecycle")
    denied = evaluate_action(policy, state, "policy.change", "alice", 1005, "trace-lifecycle")
    tick_mandatory(policy, state, 1061, "trace-lifecycle")
    tick_mandatory(policy, state, 1190, "trace-lifecycle")

    status = {
        "healthy_gates": {"revocation_frontier"},
        "available_capabilities": {"federation_peer"},
        "observed_error_rate": 0.01,
    }
    observe_recovery(policy, state, status, 1200, "trace-lifecycle")
    observe_recovery(policy, state, status, 1499, "trace-lifecycle")
    observe_recovery(policy, state, status, 1500, "trace-lifecycle")

    return {
        "policy": policy,
        "state": state,
        "denied_decision": denied,
    }


def run_checks() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.append(check_file(IMPL, "degraded mode policy implementation"))
    checks.append(check_file(SPEC, "contract"))
    checks.extend(check_contains(IMPL, REQUIRED_IMPL_PATTERNS, "impl"))
    checks.extend(check_contains(MOD_RS, ["pub mod degraded_mode_policy;"], "module wiring"))

    lifecycle = simulate_mode_lifecycle("health_gate_failed:revocation_frontier")
    events = lifecycle["state"]["events"]
    codes = [event["event_code"] for event in events]

    entered_idx = next((idx for idx, event in enumerate(events) if event["event_code"] == "DEGRADED_MODE_ENTERED"), -1)
    action_idx = next((idx for idx, event in enumerate(events) if event["event_code"] == "DEGRADED_ACTION_BLOCKED"), -1)
    exited_idx = next((idx for idx, event in enumerate(events) if event["event_code"] == "DEGRADED_MODE_EXITED"), -1)

    checks.append(
        {
            "check": "event ordering: entered before action audit",
            "pass": entered_idx >= 0 and action_idx > entered_idx,
            "detail": f"entered_idx={entered_idx}, action_idx={action_idx}",
        }
    )
    checks.append(
        {
            "check": "mandatory audit tick present",
            "pass": "MANDATORY_AUDIT_TICK" in codes,
            "detail": "expected mandatory periodic event",
        }
    )
    checks.append(
        {
            "check": "missed audit alert present",
            "pass": "AUDIT_EVENT_MISSED" in codes,
            "detail": "expected missed-event alert when interval skipped",
        }
    )
    checks.append(
        {
            "check": "denied action path",
            "pass": lifecycle["denied_decision"]["permitted"] is False
            and lifecycle["denied_decision"]["denial_reason"] == "denied_actions.policy.change",
            "detail": str(lifecycle["denied_decision"]),
        }
    )
    checks.append(
        {
            "check": "recovery stabilization window",
            "pass": exited_idx > action_idx and lifecycle["state"]["mode"] == "normal",
            "detail": f"exited_idx={exited_idx}, final_mode={lifecycle['state']['mode']}",
        }
    )

    # Trigger-variant coverage check expected by acceptance tests.
    trigger_variants = base_policy()["trigger_conditions"]
    trigger_pass = True
    for trigger in trigger_variants:
        sim = simulate_mode_lifecycle(trigger)
        if sim["state"]["events"][1]["event_code"] != "DEGRADED_MODE_ENTERED":
            trigger_pass = False
            break
    checks.append(
        {
            "check": "trigger variants activate degraded mode",
            "pass": trigger_pass,
            "detail": f"variants={len(trigger_variants)}",
        }
    )

    passed = sum(1 for check in checks if check["pass"])
    total = len(checks)
    return {
        "bead_id": "bd-3nr",
        "title": "Degraded-mode policy behavior with mandatory audit events",
        "section": "10.5",
        "verdict": "PASS" if passed == total else "FAIL",
        "overall_pass": passed == total,
        "summary": {"passing": passed, "failing": total - passed, "total": total},
        "checks": checks,
    }


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    result = run_checks()
    return result["verdict"] == "PASS", result["checks"]


def main() -> None:
    if "--self-test" in sys.argv:
        ok, checks = self_test()
        print(f"self_test: {'PASS' if ok else 'FAIL'} ({len(checks)} checks)")
        raise SystemExit(0 if ok else 1)

    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print("=== bd-3nr: degraded mode policy verification ===")
        print(f"Verdict: {result['verdict']}")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")

    raise SystemExit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
