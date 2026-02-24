#!/usr/bin/env python3
"""bd-2wsm: Epoch transition barrier protocol — verification gate."""
import json, os, re, sys
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "control_plane", "epoch_transition_barrier.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "control_plane", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_10_14", "bd-2wsm_contract.md")
BEAD, SECTION = "bd-2wsm", "10.14"

EVENT_CODES = [
    "BARRIER_PROPOSED", "BARRIER_DRAIN_ACK", "BARRIER_COMMITTED",
    "BARRIER_ABORTED", "BARRIER_TIMEOUT", "BARRIER_DRAIN_FAILED",
    "BARRIER_ABORT_SENT", "BARRIER_CONCURRENT_REJECTED",
    "BARRIER_TRANSCRIPT_EXPORTED", "BARRIER_PARTICIPANT_REGISTERED",
]
ERROR_CODES = [
    "ERR_BARRIER_CONCURRENT", "ERR_BARRIER_NO_PARTICIPANTS",
    "ERR_BARRIER_TIMEOUT", "ERR_BARRIER_DRAIN_FAILED",
    "ERR_BARRIER_ALREADY_COMPLETE", "ERR_BARRIER_INVALID_PHASE",
    "ERR_BARRIER_UNKNOWN_PARTICIPANT", "ERR_BARRIER_EPOCH_MISMATCH",
]
INVS = [
    "INV-BARRIER-ALL-ACK", "INV-BARRIER-NO-PARTIAL", "INV-BARRIER-ABORT-SAFE",
    "INV-BARRIER-SERIALIZED", "INV-BARRIER-TRANSCRIPT", "INV-BARRIER-TIMEOUT",
]

def _read(p):
    with open(p) as f: return f.read()

def _checks():
    r = []
    def ok(n, p, d=""): r.append({"check": n, "passed": p, "detail": d})
    src = _read(IMPL)

    # File existence and module wiring
    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod epoch_transition_barrier;" in _read(MOD_RS))

    # Core types
    for st in ["BarrierPhase", "DrainAck", "AbortReason", "BarrierError",
               "BarrierConfig", "TranscriptEntry", "BarrierTranscript",
               "BarrierAuditRecord", "BarrierInstance", "EpochTransitionBarrier"]:
        ok(f"struct_{st}", st in src and ("struct " + st in src or "enum " + st in src or "pub struct " + st in src), st)

    # Protocol phases
    ok("phase_proposed", "Proposed" in src, "Proposed phase")
    ok("phase_draining", "Draining" in src, "Draining phase")
    ok("phase_committed", "Committed" in src, "Committed phase")
    ok("phase_aborted", "Aborted" in src, "Aborted phase")

    # Core operations
    ok("fn_propose", "fn propose" in src, "Propose barrier")
    ok("fn_record_drain_ack", "fn record_drain_ack" in src, "Record drain ACK")
    ok("fn_try_commit", "fn try_commit" in src, "Try commit")
    ok("fn_abort", "fn abort" in src, "Abort barrier")
    ok("fn_record_drain_failure", "fn record_drain_failure" in src, "Record drain failure")
    ok("fn_check_participant_timeouts", "fn check_participant_timeouts" in src, "Check participant timeouts")
    ok("fn_register_participant", "fn register_participant" in src, "Register participant")

    # Barrier features
    ok("all_acked", "fn all_acked" in src, "All-ACK check")
    ok("missing_acks", "fn missing_acks" in src, "Missing ACKs tracking")
    ok("is_terminal", "fn is_terminal" in src, "Terminal state detection")
    ok("is_barrier_active", "fn is_barrier_active" in src, "Active barrier check")
    ok("configurable_timeout", "drain_timeout_for" in src and "participant_timeouts" in src, "Configurable per-participant timeout")

    # Transcript and audit
    ok("transcript_export", "fn export_jsonl" in src, "JSONL transcript export")
    ok("audit_log", "fn export_audit_log_jsonl" in src, "JSONL audit log export")

    # Event codes
    ec = sum(1 for c in EVENT_CODES if c in src)
    ok("event_codes", ec >= 8, f"{ec}/10")

    # Error codes
    erc = sum(1 for c in ERROR_CODES if c in src)
    ok("error_codes", erc >= 8, f"{erc}/8")

    # Invariants
    inv = sum(1 for i in INVS if i in src)
    ok("invariants", inv >= 6, f"{inv}/6")

    # Config validation
    ok("config_validation", "fn validate" in src, "Config validation")

    # Schema version
    ok("schema_version", "eb-v1.0" in src, "eb-v1.0")

    # Spec alignment
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)

    # Test coverage
    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 25, f"{test_count} tests")

    return r

def self_test():
    r = _checks()
    assert len(r) >= 25
    for x in r:
        assert "check" in x and "passed" in x
    print(f"self_test: {len(r)} checks OK", file=sys.stderr)
    return True

def main():
    logger = configure_test_logging("check_epoch_transition_barrier")
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
