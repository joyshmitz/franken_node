#!/usr/bin/env python3
"""Verification script for bd-2sx: Revocation freshness gate for risky product actions.

Checks that the revocation freshness gate artefacts are present, complete,
and internally consistent.

Usage:
    python3 scripts/check_revocation_freshness.py            # human-readable
    python3 scripts/check_revocation_freshness.py --json      # machine-readable
    python3 scripts/check_revocation_freshness.py --self-test  # smoke-test
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path
from typing import Any

SPEC = ROOT / "docs" / "specs" / "section_10_10" / "bd-2sx_contract.md"
POLICY = ROOT / "docs" / "policy" / "revocation_freshness_gate.md"
IMPL = ROOT / "crates" / "franken-node" / "src" / "security" / "revocation_freshness_gate.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "security" / "mod.rs"
UNIT_TESTS = ROOT / "tests" / "test_check_revocation_freshness.py"

EVENT_CODES = ["RFG-001", "RFG-002", "RFG-003", "RFG-004"]
INVARIANTS = [
    "INV-RFG-GATE",
    "INV-RFG-PROOF",
    "INV-RFG-DEGRADE",
    "INV-RFG-SESSION",
]
ERROR_CODES = [
    "ERR_RFG_STALE",
    "ERR_RFG_SERVICE_DOWN",
    "ERR_RFG_TAMPERED",
    "ERR_RFG_REPLAY",
    "ERR_RFG_UNAUTHENTICATED",
]
REQUIRED_TYPES = [
    "SafetyTier",
    "FreshnessProof",
    "RevocationFreshnessGate",
    "FreshnessError",
    "GateDecision",
]
REQUIRED_METHODS = [
    "fn check(",
    "fn classify_action(",
    "fn verify_proof(",
]
REQUIRED_TIERS = ["Critical", "Standard", "Advisory"]

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _safe_rel(path: Path) -> str:
    s_path, s_root = str(path), str(ROOT)
    if s_path.startswith(s_root):
        return str(path.relative_to(ROOT))
    return str(path)


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------


def check_spec_exists() -> None:
    """Spec contract file must exist."""
    ok = SPEC.is_file()
    _check(
        "spec_exists",
        ok,
        f"found: {_safe_rel(SPEC)}" if ok else f"MISSING: {_safe_rel(SPEC)}",
    )


def check_policy_exists() -> None:
    """Policy file must exist."""
    ok = POLICY.is_file()
    _check(
        "policy_exists",
        ok,
        f"found: {_safe_rel(POLICY)}" if ok else f"MISSING: {_safe_rel(POLICY)}",
    )


def check_impl_exists() -> None:
    """Rust implementation file must exist."""
    ok = IMPL.is_file()
    _check(
        "impl_exists",
        ok,
        f"found: {_safe_rel(IMPL)}" if ok else f"MISSING: {_safe_rel(IMPL)}",
    )


def check_mod_rs_registers() -> None:
    """Module must be registered in security/mod.rs."""
    if not MOD_RS.is_file():
        _check("mod_rs_registers", False, "mod.rs file missing")
        return
    text = MOD_RS.read_text()
    ok = "revocation_freshness_gate" in text
    _check("mod_rs_registers", ok, "found" if ok else "NOT FOUND in mod.rs")


def check_spec_bead_id() -> None:
    """Spec must reference bd-2sx."""
    if not SPEC.is_file():
        _check("spec_bead_id", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "bd-2sx" in text
    _check("spec_bead_id", ok, "found" if ok else "NOT FOUND")


def check_spec_section() -> None:
    """Spec must reference section 10.10."""
    if not SPEC.is_file():
        _check("spec_section_10_10", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "10.10" in text and "Hardening" in text
    _check("spec_section_10_10", ok, "found" if ok else "NOT FOUND")


def check_spec_event_codes() -> None:
    """Spec must contain all event codes."""
    if not SPEC.is_file():
        for code in EVENT_CODES:
            _check(f"spec_event_code_{code}", False, "spec file missing")
        return
    text = SPEC.read_text()
    for code in EVENT_CODES:
        ok = code in text
        _check(f"spec_event_code_{code}", ok, "found" if ok else "NOT FOUND")


def check_spec_invariants() -> None:
    """Spec must contain all invariants."""
    if not SPEC.is_file():
        for inv in INVARIANTS:
            _check(f"spec_invariant_{inv}", False, "spec file missing")
        return
    text = SPEC.read_text()
    for inv in INVARIANTS:
        ok = inv in text
        _check(f"spec_invariant_{inv}", ok, "found" if ok else "NOT FOUND")


def check_spec_error_codes() -> None:
    """Spec must contain all error codes."""
    if not SPEC.is_file():
        for code in ERROR_CODES:
            _check(f"spec_error_code_{code}", False, "spec file missing")
        return
    text = SPEC.read_text()
    for code in ERROR_CODES:
        ok = code in text
        _check(f"spec_error_code_{code}", ok, "found" if ok else "NOT FOUND")


def check_spec_tiers() -> None:
    """Spec must document all three safety tiers."""
    if not SPEC.is_file():
        _check("spec_tiers", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = all(t in text for t in REQUIRED_TIERS)
    _check(
        "spec_tiers",
        ok,
        "all three tiers documented" if ok else "missing tier documentation",
    )


def check_spec_epoch_thresholds() -> None:
    """Spec must document epoch-based thresholds (1, 5, 10)."""
    if not SPEC.is_file():
        _check("spec_epoch_thresholds", False, "spec file missing")
        return
    text = SPEC.read_text()
    has_1 = "1 epoch" in text
    has_5 = "5 epoch" in text
    has_10 = "10 epoch" in text
    ok = has_1 and has_5 and has_10
    _check(
        "spec_epoch_thresholds",
        ok,
        "epoch thresholds 1/5/10 present" if ok else "missing epoch thresholds",
    )


def check_spec_acceptance_criteria() -> None:
    """Spec must have acceptance criteria."""
    if not SPEC.is_file():
        _check("spec_acceptance_criteria", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "Acceptance Criteria" in text
    _check("spec_acceptance_criteria", ok, "found" if ok else "NOT FOUND")


def check_spec_test_scenarios() -> None:
    """Spec must have test scenarios."""
    if not SPEC.is_file():
        _check("spec_test_scenarios", False, "spec file missing")
        return
    text = SPEC.read_text()
    ok = "Scenario" in text
    _check("spec_test_scenarios", ok, "found" if ok else "NOT FOUND")


def check_spec_graceful_degradation() -> None:
    """Spec must document graceful degradation per tier."""
    if not SPEC.is_file():
        _check("spec_graceful_degradation", False, "spec file missing")
        return
    text = SPEC.read_text().lower()
    has_fail_closed = "fail-closed" in text
    has_owner_bypass = "owner-bypass" in text or "owner bypass" in text
    has_warning = "proceed-with-warning" in text or "proceed with warning" in text
    ok = has_fail_closed and has_owner_bypass and has_warning
    _check(
        "spec_graceful_degradation",
        ok,
        "fail-closed, owner-bypass, proceed-with-warning documented"
        if ok
        else "missing degradation documentation",
    )


def check_impl_required_types() -> None:
    """Implementation must define all required types."""
    if not IMPL.is_file():
        for t in REQUIRED_TYPES:
            _check(f"impl_type_{t}", False, "impl file missing")
        return
    text = IMPL.read_text()
    for t in REQUIRED_TYPES:
        ok = t in text
        _check(f"impl_type_{t}", ok, "found" if ok else "NOT FOUND")


def check_impl_required_methods() -> None:
    """Implementation must define all required methods."""
    if not IMPL.is_file():
        for m in REQUIRED_METHODS:
            label = m.replace("fn ", "").replace("(", "")
            _check(f"impl_method_{label}", False, "impl file missing")
        return
    text = IMPL.read_text()
    for m in REQUIRED_METHODS:
        label = m.replace("fn ", "").replace("(", "")
        ok = m in text
        _check(f"impl_method_{label}", ok, "found" if ok else "NOT FOUND")


def check_impl_event_codes() -> None:
    """Implementation must reference all event codes."""
    if not IMPL.is_file():
        for code in EVENT_CODES:
            _check(f"impl_event_code_{code}", False, "impl file missing")
        return
    text = IMPL.read_text()
    for code in EVENT_CODES:
        ok = code in text
        _check(f"impl_event_code_{code}", ok, "found" if ok else "NOT FOUND")


def check_impl_error_codes() -> None:
    """Implementation must reference all error codes."""
    if not IMPL.is_file():
        for code in ERROR_CODES:
            _check(f"impl_error_code_{code}", False, "impl file missing")
        return
    text = IMPL.read_text()
    for code in ERROR_CODES:
        ok = code in text
        _check(f"impl_error_code_{code}", ok, "found" if ok else "NOT FOUND")


def check_impl_invariants() -> None:
    """Implementation must reference all invariants."""
    if not IMPL.is_file():
        for inv in INVARIANTS:
            _check(f"impl_invariant_{inv}", False, "impl file missing")
        return
    text = IMPL.read_text()
    for inv in INVARIANTS:
        ok = inv in text
        _check(f"impl_invariant_{inv}", ok, "found" if ok else "NOT FOUND")


def check_impl_tiers() -> None:
    """Implementation must define all three safety tiers."""
    if not IMPL.is_file():
        _check("impl_tiers", False, "impl file missing")
        return
    text = IMPL.read_text()
    ok = all(t in text for t in REQUIRED_TIERS)
    _check("impl_tiers", ok, "all three tiers defined" if ok else "missing tiers")


def check_impl_unit_test_count() -> None:
    """Implementation must have >= 25 unit tests."""
    if not IMPL.is_file():
        _check("impl_unit_test_count", False, "impl file missing")
        return
    text = IMPL.read_text()
    count = text.count("#[test]")
    ok = count >= 25
    _check(
        "impl_unit_test_count",
        ok,
        f"{count} tests found (>= 25 required)"
        if ok
        else f"only {count} tests found (>= 25 required)",
    )


def check_impl_replay_detection() -> None:
    """Implementation must have replay detection."""
    if not IMPL.is_file():
        _check("impl_replay_detection", False, "impl file missing")
        return
    text = IMPL.read_text()
    has_nonce_set = "consumed_nonces" in text or "HashSet" in text
    has_replay_error = "ReplayDetected" in text
    ok = has_nonce_set and has_replay_error
    _check(
        "impl_replay_detection",
        ok,
        "replay detection with nonce tracking found"
        if ok
        else "replay detection incomplete",
    )


def check_impl_signature_verification() -> None:
    """Implementation must have signature verification."""
    if not IMPL.is_file():
        _check("impl_signature_verification", False, "impl file missing")
        return
    text = IMPL.read_text()
    has_sig_check = "signature" in text and "verify" in text.lower()
    has_tampered = "ProofTampered" in text
    ok = has_sig_check and has_tampered
    _check(
        "impl_signature_verification",
        ok,
        "signature verification with tamper detection found"
        if ok
        else "signature verification incomplete",
    )


def check_policy_risk_description() -> None:
    """Policy must document the risk description."""
    if not POLICY.is_file():
        _check("policy_risk_description", False, "policy file missing")
        return
    text = POLICY.read_text()
    has_desc = "Revocation" in text and "Freshness" in text
    has_section = "Risk Description" in text
    ok = has_desc and has_section
    _check(
        "policy_risk_description",
        ok,
        "risk description documented" if ok else "missing risk description",
    )


def check_policy_impact() -> None:
    """Policy must document impact assessment."""
    if not POLICY.is_file():
        _check("policy_impact", False, "policy file missing")
        return
    text = POLICY.read_text()
    ok = "Impact" in text and "Critical" in text
    _check("policy_impact", ok, "found" if ok else "NOT FOUND")


def check_policy_likelihood() -> None:
    """Policy must document likelihood assessment."""
    if not POLICY.is_file():
        _check("policy_likelihood", False, "policy file missing")
        return
    text = POLICY.read_text()
    ok = "Likelihood" in text and "High" in text
    _check("policy_likelihood", ok, "found" if ok else "NOT FOUND")


def check_policy_invariants() -> None:
    """Policy must reference all invariants."""
    if not POLICY.is_file():
        for inv in INVARIANTS:
            _check(f"policy_invariant_{inv}", False, "policy file missing")
        return
    text = POLICY.read_text()
    for inv in INVARIANTS:
        ok = inv in text
        _check(f"policy_invariant_{inv}", ok, "found" if ok else "NOT FOUND")


def check_policy_event_codes() -> None:
    """Policy must reference all event codes."""
    if not POLICY.is_file():
        for code in EVENT_CODES:
            _check(f"policy_event_code_{code}", False, "policy file missing")
        return
    text = POLICY.read_text()
    for code in EVENT_CODES:
        ok = code in text
        _check(f"policy_event_code_{code}", ok, "found" if ok else "NOT FOUND")


def check_policy_escalation() -> None:
    """Policy must document escalation procedures."""
    if not POLICY.is_file():
        _check("policy_escalation", False, "policy file missing")
        return
    text = POLICY.read_text()
    ok = "Escalation" in text and "60 second" in text.lower()
    _check(
        "policy_escalation",
        ok,
        "escalation procedures with 60s SLA documented"
        if ok
        else "escalation procedures missing or incomplete",
    )


def check_policy_evidence_requirements() -> None:
    """Policy must document evidence requirements for review."""
    if not POLICY.is_file():
        _check("policy_evidence_requirements", False, "policy file missing")
        return
    text = POLICY.read_text()
    ok = "Evidence" in text and "review" in text.lower()
    _check(
        "policy_evidence_requirements",
        ok,
        "evidence requirements for review documented"
        if ok
        else "evidence requirements missing",
    )


def check_policy_countermeasures() -> None:
    """Policy must document countermeasure details."""
    if not POLICY.is_file():
        _check("policy_countermeasures", False, "policy file missing")
        return
    text = POLICY.read_text()
    has_replay = "Replay" in text
    has_sig = "Signature" in text
    has_staleness = "Staleness" in text
    has_degradation = "Degradation" in text
    ok = has_replay and has_sig and has_staleness and has_degradation
    _check(
        "policy_countermeasures",
        ok,
        "all four countermeasures documented"
        if ok
        else "missing countermeasure documentation",
    )


def check_unit_tests_exist() -> None:
    """Unit test file must exist."""
    ok = UNIT_TESTS.is_file()
    _check(
        "unit_tests_exist",
        ok,
        f"found: {_safe_rel(UNIT_TESTS)}"
        if ok
        else f"MISSING: {_safe_rel(UNIT_TESTS)}",
    )


def check_verification_evidence() -> None:
    """Verification evidence artifact must exist and be valid."""
    p = ROOT / "artifacts" / "section_10_10" / "bd-2sx" / "verification_evidence.json"
    if not p.is_file():
        _check("verification_evidence", False, f"MISSING: {_safe_rel(p)}")
        return
    try:
        data = json.loads(p.read_text())
        ok = data.get("bead_id") == "bd-2sx" and data.get("status") == "pass"
        _check(
            "verification_evidence",
            ok,
            f"valid: {_safe_rel(p)}"
            if ok
            else "evidence has incorrect bead_id or status",
        )
    except (json.JSONDecodeError, KeyError) as exc:
        _check("verification_evidence", False, f"parse error: {exc}")


def check_verification_summary() -> None:
    """Verification summary artifact must exist."""
    p = ROOT / "artifacts" / "section_10_10" / "bd-2sx" / "verification_summary.md"
    ok = p.is_file()
    _check(
        "verification_summary",
        ok,
        f"found: {_safe_rel(p)}" if ok else f"MISSING: {_safe_rel(p)}",
    )


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_spec_exists,
    check_policy_exists,
    check_impl_exists,
    check_mod_rs_registers,
    check_spec_bead_id,
    check_spec_section,
    check_spec_event_codes,
    check_spec_invariants,
    check_spec_error_codes,
    check_spec_tiers,
    check_spec_epoch_thresholds,
    check_spec_acceptance_criteria,
    check_spec_test_scenarios,
    check_spec_graceful_degradation,
    check_impl_required_types,
    check_impl_required_methods,
    check_impl_event_codes,
    check_impl_error_codes,
    check_impl_invariants,
    check_impl_tiers,
    check_impl_unit_test_count,
    check_impl_replay_detection,
    check_impl_signature_verification,
    check_policy_risk_description,
    check_policy_impact,
    check_policy_likelihood,
    check_policy_invariants,
    check_policy_event_codes,
    check_policy_escalation,
    check_policy_evidence_requirements,
    check_policy_countermeasures,
    check_unit_tests_exist,
    check_verification_evidence,
    check_verification_summary,
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_all() -> dict[str, Any]:
    global RESULTS
    RESULTS = []
    for fn in ALL_CHECKS:
        fn()
    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["pass"])
    failed = total - passed
    return {
        "bead_id": "bd-2sx",
        "title": "revocation freshness gate for risky product actions",
        "section": "10.10",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": list(RESULTS),
    }


def self_test() -> bool:
    report = run_all()
    total, passed, failed = report["total"], report["passed"], report["failed"]
    print(f"self_test: {passed}/{total} checks pass, {failed} failing")
    if failed:
        for c in report["checks"]:
            if not c["pass"]:
                print(f"  FAIL: {c['check']} -- {c['detail']}")
    return failed == 0


def main() -> None:
    logger = configure_test_logging("check_revocation_freshness")
    parser = argparse.ArgumentParser(
        description="Verify bd-2sx: revocation freshness gate"
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)
    report = run_all()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for c in report["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"[{status}] {c['check']}: {c['detail']}")
        print(
            f"\n{report['passed']}/{report['total']} checks pass"
            f" (verdict={report['verdict']})"
        )
    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
