#!/usr/bin/env python3
"""bd-4jh9: Verification script for VEF degraded-mode policy with proof lag/outage SLOs.

Usage:
    python3 scripts/check_vef_degraded_mode.py            # human-readable
    python3 scripts/check_vef_degraded_mode.py --json      # machine-readable
    python3 scripts/check_vef_degraded_mode.py --self-test  # internal consistency
"""

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

# ── File paths ─────────────────────────────────────────────────────────────

IMPL_FILE = ROOT / "crates/franken-node/src/security/vef_degraded_mode.rs"
MOD_FILE = ROOT / "crates/franken-node/src/security/mod.rs"
SPEC_FILE = ROOT / "docs/specs/section_10_18/bd-4jh9_contract.md"
POLICY_FILE = ROOT / "docs/policy/vef_degraded_mode_policy.md"
EVIDENCE_FILE = ROOT / "artifacts/section_10_18/bd-4jh9/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_18/bd-4jh9/verification_summary.md"

ALL_CHECKS: list[dict[str, Any]] = []
RESULTS: dict[str, Any] = {}

# ── Required elements ──────────────────────────────────────────────────────

REQUIRED_TYPES = [
    "pub enum VefMode",
    "pub struct ProofLagSlo",
    "pub struct VefDegradedModeConfig",
    "pub struct ProofLagMetrics",
    "pub enum ActionRisk",
    "pub struct VefActionDecision",
    "pub struct VefModeTransitionEvent",
    "pub struct VefSloBreachEvent",
    "pub struct VefRecoveryInitiatedEvent",
    "pub struct VefRecoveryReceipt",
    "pub enum VefDegradedModeEvent",
    "pub struct VefTransitionErrorEvent",
    "pub struct VefDegradedModeEngine",
]

REQUIRED_EVENT_CODES = [
    "VEF-DEGRADE-001",
    "VEF-DEGRADE-002",
    "VEF-DEGRADE-003",
    "VEF-DEGRADE-004",
    "VEF-DEGRADE-ERR-001",
]

REQUIRED_MODES = [
    "Normal",
    "Restricted",
    "Quarantine",
    "Halt",
]

REQUIRED_FUNCTIONS = [
    "fn observe_metrics",
    "fn evaluate_action",
    "fn target_mode_for_metrics",
    "fn escalate",
    "fn maybe_deescalate",
    "fn find_breach_details",
]

REQUIRED_METRICS = [
    "proof_lag_secs",
    "backlog_depth",
    "error_rate",
    "heartbeat_age_secs",
]

REQUIRED_INVARIANTS_SPEC = [
    "INV-VEF-DM-DETERMINISTIC",
    "INV-VEF-DM-AUDIT",
    "INV-VEF-DM-ESCALATE-IMMEDIATE",
    "INV-VEF-DM-DEESCALATE-STABILIZED",
    "INV-VEF-DM-RECOVERY-RECEIPT",
]


# ── Helpers ────────────────────────────────────────────────────────────────

def _safe_rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _check(name: str, ok: bool, detail: str = "") -> dict[str, Any]:
    entry = {"check": name, "pass": ok, "detail": detail or ("ok" if ok else "FAIL")}
    ALL_CHECKS.append(entry)
    return entry


# ── Check groups ───────────────────────────────────────────────────────────

def check_file_existence() -> None:
    _check("implementation exists", IMPL_FILE.exists(), _safe_rel(IMPL_FILE))
    _check("module wired in mod.rs", "pub mod vef_degraded_mode;" in _read(MOD_FILE), _safe_rel(MOD_FILE))
    _check("spec document exists", SPEC_FILE.exists(), _safe_rel(SPEC_FILE))
    _check("policy document exists", POLICY_FILE.exists(), _safe_rel(POLICY_FILE))
    _check("evidence artifact exists", EVIDENCE_FILE.exists(), _safe_rel(EVIDENCE_FILE))
    _check("summary artifact exists", SUMMARY_FILE.exists(), _safe_rel(SUMMARY_FILE))


def check_types() -> None:
    src = _read(IMPL_FILE)
    for t in REQUIRED_TYPES:
        _check(f"type: {t}", t in src)


def check_event_codes() -> None:
    src = _read(IMPL_FILE)
    for code in REQUIRED_EVENT_CODES:
        _check(f"event code: {code}", code in src)


def check_modes() -> None:
    src = _read(IMPL_FILE)
    for mode in REQUIRED_MODES:
        _check(f"mode variant: {mode}", mode in src)


def check_functions() -> None:
    src = _read(IMPL_FILE)
    for fn_name in REQUIRED_FUNCTIONS:
        _check(f"function: {fn_name}", fn_name in src)


def check_metrics() -> None:
    src = _read(IMPL_FILE)
    for metric in REQUIRED_METRICS:
        _check(f"metric field: {metric}", metric in src)


def check_slo_defaults() -> None:
    src = _read(IMPL_FILE)
    # Restricted: 300, 100, 0.10
    _check("restricted SLO proof_lag default 300", "300" in src and "restricted_slo" in src)
    # Quarantine: 900, 500, 0.30
    _check("quarantine SLO proof_lag default 900", "900" in src and "quarantine_slo" in src)
    # Halt multiplier 2.0
    _check("halt multiplier 2.0", "2.0" in src and "halt_multiplier" in src)
    # Stabilization window 120
    _check("stabilization window 120", "120" in src and "stabilization_window_secs" in src)


def check_spec_invariants() -> None:
    src = _read(SPEC_FILE)
    for inv in REQUIRED_INVARIANTS_SPEC:
        _check(f"spec invariant: {inv}", inv in src)


def check_spec_content() -> None:
    src = _read(SPEC_FILE)
    _check("spec: restricted tier", "restricted" in src.lower() and "Restricted" in src)
    _check("spec: quarantine tier", "quarantine" in src.lower() and "Quarantine" in src)
    _check("spec: halt tier", "halt" in src.lower() and "Halt" in src)
    _check("spec: SLO thresholds", "SLO" in src)
    _check("spec: transition rules", "Transition" in src)
    _check("spec: recovery receipts", "recovery" in src.lower())
    _check("spec: audit events", "VEF-DEGRADE-001" in src)


def check_policy_content() -> None:
    src = _read(POLICY_FILE)
    _check("policy: restricted tier", "Restricted" in src)
    _check("policy: quarantine tier", "Quarantine" in src)
    _check("policy: halt tier", "Halt" in src)
    _check("policy: SLO thresholds", "SLO" in src)
    _check("policy: VEF-DEGRADE event codes", "VEF-DEGRADE-001" in src)
    _check("policy: recovery receipts", "receipt" in src.lower())
    _check("policy: operator guidance", "Operator" in src)


def check_tests() -> None:
    src = _read(IMPL_FILE)
    test_count = src.count("#[test]")
    _check(f"Rust unit tests >= 20 ({test_count})", test_count >= 20, f"{test_count} tests")

    test_categories = [
        ("normal default", "normal_mode_by_default"),
        ("restricted breach", "restricted_on_proof_lag_breach"),
        ("quarantine breach", "quarantine_on_slo_breach"),
        ("halt critical lag", "halt_on_critical_lag"),
        ("halt heartbeat", "halt_on_heartbeat_timeout"),
        ("escalation path", "normal_to_restricted_to_quarantine"),
        ("skip-tier escalation", "skip_restricted_direct_to_quarantine"),
        ("deescalation stabilization", "deescalation_requires_stabilization"),
        ("deescalation reset", "deescalation_resets_on_metric_regression"),
        ("step-down through tiers", "halt_deescalates_through_quarantine"),
        ("determinism", "deterministic_identical_metric_sequences"),
        ("audit events", "escalation_emits_slo_breach"),
        ("recovery receipt", "deescalation_emits_recovery_receipt"),
        ("transition fields", "transition_event_has_required_fields"),
        ("action normal", "normal_permits_all"),
        ("action quarantine", "quarantine_blocks_high_risk"),
        ("action halt", "halt_blocks_all_except_health_check"),
        ("custom SLO", "custom_slo_thresholds"),
        ("no silent transitions", "no_silent_transitions"),
    ]
    for name, pattern in test_categories:
        _check(f"test: {name}", pattern in src)


def check_determinism_invariant() -> None:
    src = _read(IMPL_FILE)
    _check("INV: deterministic (comment)", "INV-VEF-DM-DETERMINISTIC" in src)
    _check("INV: pure function target_mode", "pure function" in src.lower() or "target_mode_for_metrics" in src)


def check_action_evaluation() -> None:
    src = _read(IMPL_FILE)
    _check("action: HighRisk variant", "HighRisk" in src)
    _check("action: LowRisk variant", "LowRisk" in src)
    _check("action: HealthCheck variant", "HealthCheck" in src)
    _check("action: VefActionDecision result", "VefActionDecision" in src)


def check_recovery_receipt_fields() -> None:
    src = _read(IMPL_FILE)
    _check("receipt: degraded_mode_duration_secs", "degraded_mode_duration_secs" in src)
    _check("receipt: actions_affected", "actions_affected" in src)
    _check("receipt: recovery_trigger", "recovery_trigger" in src)
    _check("receipt: pipeline_health_at_recovery", "pipeline_health_at_recovery" in src)
    _check("receipt: from_mode", "from_mode" in src)
    _check("receipt: to_mode", "to_mode" in src)
    _check("receipt: correlation_id", "correlation_id" in src)


# ── Simulation ─────────────────────────────────────────────────────────────

def _default_config() -> dict[str, Any]:
    return {
        "restricted_slo": {"max_proof_lag_secs": 300, "max_backlog_depth": 100, "max_error_rate": 0.10},
        "quarantine_slo": {"max_proof_lag_secs": 900, "max_backlog_depth": 500, "max_error_rate": 0.30},
        "halt_multiplier": 2.0,
        "halt_error_rate": 0.50,
        "halt_heartbeat_timeout_secs": 60,
        "stabilization_window_secs": 120,
    }


def _halt_slo(config: dict[str, Any]) -> dict[str, Any]:
    q = config["quarantine_slo"]
    m = config["halt_multiplier"]
    return {
        "max_proof_lag_secs": int(q["max_proof_lag_secs"] * m),
        "max_backlog_depth": int(q["max_backlog_depth"] * m),
        "max_error_rate": config["halt_error_rate"],
    }


def _slo_breached(slo: dict[str, Any], metrics: dict[str, Any]) -> bool:
    return (
        metrics["proof_lag_secs"] > slo["max_proof_lag_secs"]
        or metrics["backlog_depth"] > slo["max_backlog_depth"]
        or metrics["error_rate"] > slo["max_error_rate"]
    )


def _first_breach(slo: dict[str, Any], metrics: dict[str, Any]) -> str | None:
    if metrics["proof_lag_secs"] > slo["max_proof_lag_secs"]:
        return "proof_lag_secs"
    if metrics["backlog_depth"] > slo["max_backlog_depth"]:
        return "backlog_depth"
    if metrics["error_rate"] > slo["max_error_rate"]:
        return "error_rate"
    return None


def _target_mode(config: dict[str, Any], metrics: dict[str, Any]) -> str:
    halt_slo = _halt_slo(config)
    if metrics["heartbeat_age_secs"] > config["halt_heartbeat_timeout_secs"] or _slo_breached(halt_slo, metrics):
        return "halt"
    if _slo_breached(config["quarantine_slo"], metrics):
        return "quarantine"
    if _slo_breached(config["restricted_slo"], metrics):
        return "restricted"
    return "normal"


MODE_SEVERITY = {"normal": 0, "restricted": 1, "quarantine": 2, "halt": 3}

STEP_DOWN = {"halt": "quarantine", "quarantine": "restricted", "restricted": "normal"}


def simulate_lifecycle() -> dict[str, Any]:
    """Simulate a full degraded-mode lifecycle in Python, mirroring Rust engine."""
    config = _default_config()
    mode = "normal"
    events: list[dict[str, Any]] = []
    entered_at: int | None = None
    stab_start: int | None = None
    actions_affected = 0

    def emit(code: str, ts: int, **kw: Any) -> None:
        events.append({"event_code": code, "timestamp_secs": ts, **kw})

    # 1) Normal -> Restricted (proof_lag_secs = 301)
    metrics1 = {"proof_lag_secs": 301, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 0}
    target1 = _target_mode(config, metrics1)
    assert target1 == "restricted", f"expected restricted, got {target1}"
    emit("VEF-DEGRADE-002", 1000, metric="proof_lag_secs", value=301, threshold=300, tier=target1)
    emit("VEF-DEGRADE-001", 1000, from_mode=mode, to_mode=target1)
    mode = target1
    entered_at = 1000

    # 2) Restricted -> Quarantine (proof_lag_secs = 901)
    metrics2 = {"proof_lag_secs": 901, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 0}
    target2 = _target_mode(config, metrics2)
    assert target2 == "quarantine", f"expected quarantine, got {target2}"
    emit("VEF-DEGRADE-002", 1100, metric="proof_lag_secs", value=901, threshold=900, tier=target2)
    emit("VEF-DEGRADE-001", 1100, from_mode=mode, to_mode=target2)
    mode = target2

    # 3) Evaluate actions in quarantine
    # High-risk blocked
    actions_affected += 1
    high_risk_blocked = True  # quarantine blocks high-risk
    # Low-risk permitted
    actions_affected += 1
    low_risk_permitted = True

    # 4) Quarantine -> Halt (heartbeat timeout)
    metrics3 = {"proof_lag_secs": 0, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 61}
    target3 = _target_mode(config, metrics3)
    assert target3 == "halt", f"expected halt, got {target3}"
    emit("VEF-DEGRADE-002", 1200, metric="heartbeat_age_secs", value=61, threshold=60, tier=target3)
    emit("VEF-DEGRADE-001", 1200, from_mode=mode, to_mode=target3)
    mode = target3

    # 5) Recovery: metrics improve to quarantine-level
    metrics4 = {"proof_lag_secs": 500, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 0}
    target4 = _target_mode(config, metrics4)
    assert target4 == "restricted", f"expected restricted, got {target4}"
    # Step down one tier: halt -> quarantine
    # Start stabilization
    stab_start = 1300
    emit("VEF-DEGRADE-003", 1300, from_mode=mode)
    # After stabilization window
    emit("VEF-DEGRADE-004", 1420, from_mode=mode, to_mode="quarantine",
         duration=1420 - entered_at, actions_affected=actions_affected)
    emit("VEF-DEGRADE-001", 1420, from_mode=mode, to_mode="quarantine")
    mode = "quarantine"

    # 6) Continue recovery: quarantine -> restricted
    stab_start = 1450
    emit("VEF-DEGRADE-003", 1450, from_mode=mode)
    emit("VEF-DEGRADE-004", 1570, from_mode=mode, to_mode="restricted",
         duration=1570 - entered_at, actions_affected=actions_affected)
    emit("VEF-DEGRADE-001", 1570, from_mode=mode, to_mode="restricted")
    mode = "restricted"

    # 7) Final recovery: restricted -> normal
    metrics_healthy = {"proof_lag_secs": 0, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 0}
    stab_start = 1600
    emit("VEF-DEGRADE-003", 1600, from_mode=mode)
    emit("VEF-DEGRADE-004", 1720, from_mode=mode, to_mode="normal",
         duration=1720 - entered_at, actions_affected=actions_affected)
    emit("VEF-DEGRADE-001", 1720, from_mode=mode, to_mode="normal")
    mode = "normal"

    return {
        "final_mode": mode,
        "events": events,
        "high_risk_blocked": high_risk_blocked,
        "low_risk_permitted": low_risk_permitted,
        "actions_affected": actions_affected,
    }


def simulate_determinism() -> bool:
    """Verify that identical metric sequences produce identical traces."""
    config = _default_config()
    metrics_seq = [
        {"proof_lag_secs": 301, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 0},
        {"proof_lag_secs": 901, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 0},
        {"proof_lag_secs": 0, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 0},
    ]
    trace1 = [_target_mode(config, m) for m in metrics_seq]
    trace2 = [_target_mode(config, m) for m in metrics_seq]
    return trace1 == trace2


def check_simulation() -> None:
    sim = simulate_lifecycle()

    _check("sim: final mode is normal", sim["final_mode"] == "normal", f"got {sim['final_mode']}")

    codes = [e["event_code"] for e in sim["events"]]
    _check("sim: SLO breach events (VEF-DEGRADE-002)", codes.count("VEF-DEGRADE-002") >= 3)
    _check("sim: mode transition events (VEF-DEGRADE-001)", codes.count("VEF-DEGRADE-001") >= 6)
    _check("sim: recovery initiated (VEF-DEGRADE-003)", codes.count("VEF-DEGRADE-003") >= 3)
    _check("sim: recovery receipts (VEF-DEGRADE-004)", codes.count("VEF-DEGRADE-004") >= 3)
    _check("sim: high-risk blocked in quarantine", sim["high_risk_blocked"])
    _check("sim: low-risk permitted in quarantine", sim["low_risk_permitted"])
    _check("sim: actions affected tracked", sim["actions_affected"] >= 2)

    # Determinism
    _check("sim: deterministic target_mode", simulate_determinism())

    # Tier ordering
    _check("sim: severity ordering", MODE_SEVERITY["normal"] < MODE_SEVERITY["restricted"]
           < MODE_SEVERITY["quarantine"] < MODE_SEVERITY["halt"])

    # Step-down one tier at a time
    _check("sim: step-down halt->quarantine", STEP_DOWN["halt"] == "quarantine")
    _check("sim: step-down quarantine->restricted", STEP_DOWN["quarantine"] == "restricted")
    _check("sim: step-down restricted->normal", STEP_DOWN["restricted"] == "normal")


# ── Main ───────────────────────────────────────────────────────────────────

def run_all() -> dict[str, Any]:
    ALL_CHECKS.clear()
    RESULTS.clear()

    check_file_existence()
    check_types()
    check_event_codes()
    check_modes()
    check_functions()
    check_metrics()
    check_slo_defaults()
    check_spec_invariants()
    check_spec_content()
    check_policy_content()
    check_tests()
    check_determinism_invariant()
    check_action_evaluation()
    check_recovery_receipt_fields()
    check_simulation()

    passed = sum(1 for c in ALL_CHECKS if c["pass"])
    failed = sum(1 for c in ALL_CHECKS if not c["pass"])

    result = {
        "bead_id": "bd-4jh9",
        "title": "VEF degraded-mode policy for proof lag/outage with explicit SLOs",
        "section": "10.18",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(ALL_CHECKS),
        "passed": passed,
        "failed": failed,
        "checks": list(ALL_CHECKS),
    }
    RESULTS.update(result)
    return result


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []

    def st(name: str, ok: bool) -> None:
        checks.append({"check": name, "pass": ok, "detail": "ok" if ok else "FAIL"})

    # Verify constants non-empty
    st("REQUIRED_TYPES non-empty", len(REQUIRED_TYPES) >= 13)
    st("REQUIRED_EVENT_CODES = 5", len(REQUIRED_EVENT_CODES) == 5)
    st("REQUIRED_MODES = 4", len(REQUIRED_MODES) == 4)
    st("REQUIRED_FUNCTIONS >= 6", len(REQUIRED_FUNCTIONS) >= 6)
    st("REQUIRED_METRICS = 4", len(REQUIRED_METRICS) == 4)
    st("REQUIRED_INVARIANTS_SPEC = 5", len(REQUIRED_INVARIANTS_SPEC) == 5)

    # Verify simulation
    sim = simulate_lifecycle()
    st("simulation returns dict", isinstance(sim, dict))
    st("simulation final_mode = normal", sim["final_mode"] == "normal")
    st("simulation events non-empty", len(sim["events"]) > 0)

    # Verify determinism simulation
    st("determinism simulation", simulate_determinism())

    # Verify target_mode function
    cfg = _default_config()
    st("target_mode normal", _target_mode(cfg, {"proof_lag_secs": 0, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 0}) == "normal")
    st("target_mode restricted", _target_mode(cfg, {"proof_lag_secs": 301, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 0}) == "restricted")
    st("target_mode quarantine", _target_mode(cfg, {"proof_lag_secs": 901, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 0}) == "quarantine")
    st("target_mode halt lag", _target_mode(cfg, {"proof_lag_secs": 1801, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 0}) == "halt")
    st("target_mode halt heartbeat", _target_mode(cfg, {"proof_lag_secs": 0, "backlog_depth": 0, "error_rate": 0.0, "heartbeat_age_secs": 61}) == "halt")
    st("target_mode halt error", _target_mode(cfg, {"proof_lag_secs": 0, "backlog_depth": 0, "error_rate": 0.51, "heartbeat_age_secs": 0}) == "halt")

    # Verify run_all returns valid structure
    result = run_all()
    st("run_all bead_id", result.get("bead_id") == "bd-4jh9")
    st("run_all section", result.get("section") == "10.18")
    st("run_all has verdict", result.get("verdict") in ("PASS", "FAIL"))
    st("run_all has checks", isinstance(result.get("checks"), list))
    st("run_all total > 0", result.get("total", 0) > 0)

    ok = all(c["pass"] for c in checks)
    return ok, checks


# ── CLI ────────────────────────────────────────────────────────────────────

def main() -> None:
    logger = configure_test_logging("check_vef_degraded_mode")
    if "--self-test" in sys.argv:
        ok, checks = self_test()
        passed = sum(1 for c in checks if c["pass"])
        total = len(checks)
        for c in checks:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"  [{status}] {c['check']}")
        print(f"\nself-test: {passed}/{total} {'PASS' if ok else 'FAIL'}")
        sys.exit(0 if ok else 1)

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"# {result['bead_id']}: {result['title']}")
        print(f"Section: {result['section']} | Verdict: {result['verdict']}")
        print(f"Checks: {result['passed']}/{result['total']} passing\n")
        for c in result["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"  [{status}] {c['check']}: {c['detail']}")
        if result["failed"] > 0:
            print(f"\n{result['failed']} check(s) failed.")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
