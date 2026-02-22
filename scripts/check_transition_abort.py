#!/usr/bin/env python3
"""bd-1vsr: Transition abort semantics — verification gate."""
import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "control_plane", "transition_abort.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "control_plane", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_10_14", "bd-1vsr_contract.md")
BEAD, SECTION = "bd-1vsr", "10.14"

EVENT_CODES = [
    "TRANSITION_ABORTED", "FORCE_TRANSITION_APPLIED", "TRANSITION_ABORT_REJECTED",
    "ABORT_PARTICIPANT_NOTIFIED", "FORCE_POLICY_VALIDATED", "FORCE_POLICY_REJECTED",
    "ABORT_EPOCH_CONFIRMED", "FORCE_EPOCH_ADVANCED", "ABORT_EVENT_PERSISTED",
    "ABORT_RETRY_ALLOWED",
]
ERROR_CODES = [
    "ERR_ABORT_NO_BARRIER", "ERR_FORCE_NO_OPERATOR", "ERR_FORCE_NO_REASON",
    "ERR_FORCE_OVER_LIMIT", "ERR_FORCE_UNKNOWN_PARTICIPANT",
    "ERR_ABORT_ALREADY_TERMINAL", "ERR_FORCE_ALL_SKIPPED", "ERR_ABORT_INVALID_EPOCH",
]
INVS = [
    "INV-ABORT-NO-PARTIAL", "INV-ABORT-ALL-NOTIFIED",
    "INV-ABORT-FORCE-EXPLICIT", "INV-ABORT-FORCE-SCOPED",
    "INV-ABORT-FORCE-AUDITED", "INV-ABORT-FORCE-BOUNDED",
]

def _read(p):
    with open(p) as f: return f.read()

def _checks():
    r = []
    def ok(n, p, d=""): r.append({"check": n, "passed": p, "detail": d})
    src = _read(IMPL)

    # File existence and module wiring
    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod transition_abort;" in _read(MOD_RS))

    # Core types
    for st in ["TransitionAbortReason", "ParticipantAbortState", "TransitionAbortEvent",
               "ForceTransitionPolicy", "AbortError", "ForceTransitionEvent",
               "AbortAuditRecord", "TransitionAbortManager"]:
        ok(f"struct_{st}", st in src and ("struct " + st in src or "enum " + st in src or "pub struct " + st in src), st)

    # Abort reasons
    ok("reason_timeout", "Timeout" in src and "elapsed_ms" in src, "Timeout abort reason")
    ok("reason_cancellation", "Cancellation" in src and "source" in src, "Cancellation abort reason")
    ok("reason_participant_failure", "ParticipantFailure" in src, "Participant failure reason")

    # Core operations
    ok("fn_validate_force_policy", "fn validate_force_policy" in src, "Validate force policy")
    ok("fn_record_abort", "fn record_abort" in src, "Record abort")
    ok("fn_record_force_transition", "fn record_force_transition" in src, "Record force transition")
    ok("fn_verify_no_partial_state", "fn verify_no_partial_state" in src, "Verify no partial state")
    ok("fn_policy_hash", "fn policy_hash" in src, "Policy hash computation")

    # Force policy fields
    ok("force_skippable", "skippable_participants" in src, "Skippable participants field")
    ok("force_max_skippable", "max_skippable" in src, "Max skippable bound")
    ok("force_operator_id", "operator_id" in src, "Operator identity field")
    ok("force_audit_reason", "audit_reason" in src, "Audit reason field")

    # Audit and export
    ok("audit_log", "fn export_audit_log_jsonl" in src, "JSONL audit export")

    # Event codes
    ec = sum(1 for c in EVENT_CODES if c in src)
    ok("event_codes", ec >= 8, f"{ec}/10")

    # Error codes
    erc = sum(1 for c in ERROR_CODES if c in src)
    ok("error_codes", erc >= 8, f"{erc}/8")

    # Invariants
    inv = sum(1 for i in INVS if i in src)
    ok("invariants", inv >= 6, f"{inv}/6")

    # Schema version
    ok("schema_version", "ta-v1.0" in src, "ta-v1.0")

    # Spec alignment
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)

    # Test coverage
    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 20, f"{test_count} tests")

    return r

def self_test():
    r = _checks()
    assert len(r) >= 25
    for x in r:
        assert "check" in x and "passed" in x
    print(f"self_test: {len(r)} checks OK", file=sys.stderr)
    return True

def main():
    as_json = "--json" in sys.argv
    if "--self-test" in sys.argv: self_test(); return
    results = _checks(); p = sum(1 for x in results if x["passed"]); t = len(results); v = "PASS" if p == t else "FAIL"
    if as_json:
        print(json.dumps({"bead_id": BEAD, "section": SECTION, "gate_script": os.path.basename(__file__), "checks_passed": p, "checks_total": t, "verdict": v, "checks": results}, indent=2))
    else:
        for x in results: print(f"  [{'PASS' if x['passed'] else 'FAIL'}] {x['check']}: {x['detail']}")
        print(f"\n{BEAD}: {p}/{t} checks — {v}")
    sys.exit(0 if v == "PASS" else 1)

if __name__ == "__main__": main()
