#!/usr/bin/env python3
"""bd-2wsm: Epoch transition barrier protocol — verification gate."""
import json
import os
import re
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
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
    "INV-BARRIER-ALL-ACK", "INV-BARRIER-NO-PARTIAL",
    "INV-BARRIER-ABORT-SAFE", "INV-BARRIER-SERIALIZED",
    "INV-BARRIER-TRANSCRIPT", "INV-BARRIER-TIMEOUT",
]

def _read(p):
    with open(p) as f: return f.read()

def _checks():
    r = []
    def ok(n, p, d=""): r.append({"check": n, "passed": p, "detail": d})
    src = _read(IMPL)
    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod epoch_transition_barrier;" in _read(MOD_RS))

    # Barrier phases
    phases = ["Proposed", "Draining", "Committed", "Aborted"]
    ok("barrier_phases", all(p in src for p in phases), f"{len(phases)} phases")

    # Key structs/enums
    for st in ["EpochTransitionBarrier", "BarrierInstance", "BarrierPhase",
               "DrainAck", "AbortReason", "BarrierError", "BarrierConfig",
               "BarrierTranscript", "TranscriptEntry", "BarrierAuditRecord"]:
        ok(f"struct_{st}", st in src and ("struct " + st in src or "enum " + st in src or "pub type " + st in src), st)

    # Core operations
    ok("propose", "fn propose" in src, "Barrier proposal")
    ok("record_drain_ack", "fn record_drain_ack" in src, "Drain ACK recording")
    ok("try_commit", "fn try_commit" in src, "Commit attempt")
    ok("abort", "fn abort" in src, "Barrier abort")
    ok("record_drain_failure", "fn record_drain_failure" in src, "Drain failure handling")
    ok("check_participant_timeouts", "fn check_participant_timeouts" in src, "Timeout checking")
    ok("register_participant", "fn register_participant" in src, "Participant registration")
    ok("export_jsonl", "fn export_jsonl" in src, "JSONL export")

    # Invariant enforcement
    ok("all_acked_check", "fn all_acked" in src, "INV-BARRIER-ALL-ACK")
    ok("missing_acks", "fn missing_acks" in src, "Missing ACK tracking")
    ok("is_terminal", "fn is_terminal" in src, "Terminal state check")
    ok("serialized_barrier", "is_barrier_active" in src and "ConcurrentBarrier" in src, "INV-BARRIER-SERIALIZED")
    ok("epoch_mismatch", "EpochMismatch" in src and "target_epoch != current_epoch + 1" in src, "Epoch validation")

    # Event and error codes
    ok("event_codes", sum(1 for c in EVENT_CODES if c in src) >= 10, f"{sum(1 for c in EVENT_CODES if c in src)}/10")
    ok("error_codes", sum(1 for c in ERROR_CODES if c in src) >= 8, f"{sum(1 for c in ERROR_CODES if c in src)}/8")
    ok("invariant_markers", sum(1 for i in INVS if i in src) >= 6, f"{sum(1 for i in INVS if i in src)}/6")

    # Schema version and config
    ok("schema_version", "eb-v1.0" in src, "eb-v1.0")
    ok("default_timeout", "DEFAULT_BARRIER_TIMEOUT_MS" in src and "DEFAULT_DRAIN_TIMEOUT_MS" in src, "Timeout defaults")
    ok("config_validate", "fn validate" in src, "Config validation")
    ok("participant_timeout_override", "participant_timeouts" in src and "drain_timeout_for" in src, "Per-participant timeouts")

    # Spec and tests
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)
    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 30, f"{test_count} tests")

    return r

def self_test():
    r = _checks()
    assert len(r) >= 25
    for x in r:
        assert "check" in x and "passed" in x
    print(f"self_test: {len(r)} checks OK", file=sys.stderr)
    return True

def main():
    logger = configure_test_logging("check_epoch_barrier")
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
