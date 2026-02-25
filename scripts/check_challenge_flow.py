#!/usr/bin/env python3
"""Verification script for bd-29yx: suspicious-artifact challenge flow."""

import json
import os
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates/franken-node/src/security/challenge_flow.rs")
MOD_RS = os.path.join(ROOT, "crates/franken-node/src/security/mod.rs")
SPEC = os.path.join(ROOT, "docs/specs/section_10_14/bd-29yx_contract.md")
TRANSCRIPT = os.path.join(ROOT, "artifacts/10.14/challenge_flow_transcript.json")


def _check(name: str, passed: bool, detail: str = "") -> dict:
    return {"check": name, "pass": passed, "detail": detail or ("found" if passed else "NOT FOUND")}


def _file_exists(path: str, label: str) -> dict:
    exists = os.path.isfile(path)
    return _check(f"file: {label}", exists,
                  f"exists: {os.path.relpath(path, ROOT)}" if exists else f"missing: {os.path.relpath(path, ROOT)}")


def run_checks() -> list[dict]:
    checks = []

    # File existence
    checks.append(_file_exists(IMPL, "implementation"))
    checks.append(_file_exists(SPEC, "spec contract"))
    checks.append(_file_exists(TRANSCRIPT, "challenge transcript artifact"))

    # Module registered
    with open(MOD_RS) as f:
        mod_src = f.read()
    checks.append(_check("module registered in mod.rs", "pub mod challenge_flow;" in mod_src))

    with open(IMPL) as f:
        src = f.read()

    # Types
    for ty in ["pub struct ChallengeId", "pub struct ArtifactId",
               "pub enum SuspicionReason", "pub enum RequiredProofType",
               "pub enum ChallengeState", "pub struct ProofSubmission",
               "pub struct ChallengeConfig", "pub struct ChallengeAuditEntry",
               "pub struct ChallengeError", "pub struct ChallengeMetrics",
               "pub struct Challenge", "pub struct ChallengeFlowController"]:
        checks.append(_check(f"type: {ty}", ty in src))

    # State variants
    for state in ["Pending", "ChallengeIssued", "ProofReceived", "ProofVerified", "Denied", "Promoted"]:
        checks.append(_check(f"state: {state}", state in src))

    # SuspicionReason variants
    for reason in ["UnexpectedProvenance", "AgeAnomaly", "FormatDeviation", "OperatorOverride", "PolicyRule"]:
        checks.append(_check(f"reason: {reason}", reason in src))

    # Methods
    for method in ["fn issue_challenge(", "fn submit_proof(", "fn verify_proof(",
                   "fn promote(", "fn deny(", "fn enforce_timeouts(",
                   "fn audit_query(", "fn challenge_audit(",
                   "fn get_challenge(", "fn active_challenges(",
                   "fn metrics(", "fn audit_log(",
                   "fn is_terminal(", "fn valid_transitions(",
                   "fn can_transition_to(", "fn is_timed_out("]:
        checks.append(_check(f"method: {method}", method in src))

    # Event codes
    for code in ["CHALLENGE_ISSUED", "CHALLENGE_PROOF_RECEIVED", "CHALLENGE_VERIFIED",
                 "CHALLENGE_TIMED_OUT", "CHALLENGE_DENIED", "CHALLENGE_PROMOTED"]:
        checks.append(_check(f"event_code: {code}", code in src))

    # Error codes
    for code in ["ERR_INVALID_TRANSITION", "ERR_CHALLENGE_ACTIVE", "ERR_NO_ACTIVE_CHALLENGE"]:
        checks.append(_check(f"error_code: {code}", code in src))

    # Invariants
    for inv in ["INV-CHALLENGE-DEFER", "INV-CHALLENGE-TIMEOUT-DENY",
                "INV-CHALLENGE-AUDIT", "INV-CHALLENGE-VALID-TRANSITIONS"]:
        checks.append(_check(f"invariant: {inv}", inv in src))

    # Serde + SHA-256
    checks.append(_check("serde derives", "Serialize" in src and "Deserialize" in src))
    checks.append(_check("SHA-256 for audit chain", "Sha256" in src))

    # Tests
    test_names = [
        "test_pending_valid_transitions",
        "test_issued_valid_transitions",
        "test_received_valid_transitions",
        "test_verified_valid_transitions",
        "test_denied_is_terminal",
        "test_promoted_is_terminal",
        "test_denied_to_promoted_invalid",
        "test_promoted_to_denied_invalid",
        "test_state_labels",
        "test_issue_challenge",
        "test_issue_increments_metrics",
        "test_duplicate_challenge_rejected",
        "test_can_issue_after_resolved",
        "test_full_happy_path",
        "test_deny_from_issued",
        "test_deny_from_proof_received",
        "test_deny_from_verified",
        "test_promote_from_issued_fails",
        "test_promote_from_proof_received_fails",
        "test_verify_from_issued_fails",
        "test_submit_proof_to_denied_fails",
        "test_timeout_denies_challenge",
        "test_no_timeout_before_deadline",
        "test_timeout_does_not_affect_terminal",
        "test_timeout_disabled",
        "test_audit_log_populated",
        "test_audit_query_by_artifact",
        "test_audit_query_by_challenge",
        "test_audit_hash_chain",
        "test_audit_first_entry_has_zero_prev_hash",
        "test_active_challenges",
        "test_active_challenges_excludes_terminal",
        "test_suspicion_reason_labels",
        "test_required_proof_type_labels",
        "test_event_codes_defined",
        "test_invariant_tags_defined",
        "test_error_display",
        "test_error_serde_roundtrip",
        "test_challenge_is_timed_out",
        "test_metrics_after_full_flow",
        "test_challenge_state_serde",
        "test_challenge_metrics_serde",
    ]
    for test in test_names:
        checks.append(_check(f"test: {test}", f"fn {test}(" in src))

    # Unit test count
    test_count = len(re.findall(r"#\[test\]", src))
    checks.append(_check("unit test count", test_count >= 35,
                          f"{test_count} tests (minimum 35)"))

    # Transcript artifact
    if os.path.isfile(TRANSCRIPT):
        with open(TRANSCRIPT) as f:
            data = json.load(f)
        transcripts = data.get("transcripts", [])
        checks.append(_check("transcript has entries", len(transcripts) >= 3,
                              f"{len(transcripts)} transcripts (minimum 3)"))
    else:
        checks.append(_check("transcript has entries", False, "file missing"))

    return checks


def self_test():
    checks = run_checks()
    total = len(checks)
    passing = sum(1 for c in checks if c["pass"])
    failing = total - passing
    print(f"self_test: {passing}/{total} checks pass, {failing} failing")
    if failing:
        for c in checks:
            if not c["pass"]:
                print(f"  FAIL: {c['check']} — {c['detail']}")
    return failing == 0


def main():
    logger = configure_test_logging("check_challenge_flow")
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)

    checks = run_checks()
    total = len(checks)
    passing = sum(1 for c in checks if c["pass"])
    failing = total - passing

    test_count = len(re.findall(r"#\[test\]", open(IMPL).read())) if os.path.isfile(IMPL) else 0

    if args.json:
        result = {
            "bead_id": "bd-29yx",
            "title": "Suspicious-artifact challenge flow",
            "section": "10.14",
            "overall_pass": failing == 0,
            "verdict": "PASS" if failing == 0 else "FAIL",
            "test_count": test_count,
            "summary": {"passing": passing, "failing": failing, "total": total},
            "checks": checks,
        }
        print(json.dumps(result, indent=2))
    else:
        for c in checks:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"[{status}] {c['check']}: {c['detail']}")
        print(f"\n{passing}/{total} checks pass")

    sys.exit(0 if failing == 0 else 1)


if __name__ == "__main__":
    main()
