#!/usr/bin/env python3
"""bd-1cs7: Three-phase cancellation protocol (REQUEST -> DRAIN -> FINALIZE) — verification gate."""
import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "control_plane", "cancellation_protocol.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "control_plane", "mod.rs")
LIFECYCLE = os.path.join(ROOT, "crates", "franken-node", "src", "connector", "lifecycle.rs")
ROLLOUT = os.path.join(ROOT, "crates", "franken-node", "src", "connector", "rollout_state.rs")
HEALTH = os.path.join(ROOT, "crates", "franken-node", "src", "connector", "health_gate.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_10_15", "bd-1cs7_contract.md")
TIMING_CSV = os.path.join(ROOT, "artifacts", "10.15", "cancel_protocol_timing.csv")
CONFORMANCE = os.path.join(ROOT, "tests", "conformance", "cancel_drain_finalize.rs")
EVIDENCE = os.path.join(ROOT, "artifacts", "section_10_15", "bd-1cs7", "verification_evidence.json")
SUMMARY = os.path.join(ROOT, "artifacts", "section_10_15", "bd-1cs7", "verification_summary.md")
BEAD, SECTION = "bd-1cs7", "10.15"

EVENT_CODES = ["CAN-001", "CAN-002", "CAN-003", "CAN-004", "CAN-005", "CAN-006"]
ERROR_CODES = [
    "ERR_CANCEL_INVALID_PHASE", "ERR_CANCEL_ALREADY_FINAL",
    "ERR_CANCEL_DRAIN_TIMEOUT", "ERR_CANCEL_LEAK",
]
INVARIANTS = [
    "INV-CANP-THREE-PHASE", "INV-CANP-NO-NEW-WORK", "INV-CANP-DRAIN-BOUNDED",
    "INV-CANP-FINALIZE-CLEAN", "INV-CANP-IDEMPOTENT", "INV-CANP-AUDIT-COMPLETE",
]
PHASES = ["Idle", "CancelRequested", "Draining", "DrainComplete", "Finalizing", "Finalized"]

def _read(p):
    with open(p) as f:
        return f.read()

def _checks():
    r = []
    def ok(n, p, d=""):
        r.append({"check": n, "passed": p, "detail": d})

    src = _read(IMPL)

    # --- File existence ---
    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod cancellation_protocol;" in _read(MOD_RS))
    ok("spec_contract_exists", os.path.isfile(SPEC), SPEC)
    ok("conformance_test_exists", os.path.isfile(CONFORMANCE), CONFORMANCE)
    ok("timing_csv_exists", os.path.isfile(TIMING_CSV), TIMING_CSV)
    ok("evidence_exists", os.path.isfile(EVIDENCE), EVIDENCE)
    ok("summary_exists", os.path.isfile(SUMMARY), SUMMARY)

    # --- Core types ---
    for st in ["CancelPhase", "CancelProtocolError", "DrainConfig", "CancelAuditEvent",
               "ResourceTracker", "CancellationRecord", "CancellationProtocol"]:
        ok(f"type_{st}", st in src and ("struct " + st in src or "enum " + st in src or "pub struct " + st in src), st)

    # --- FSM phases ---
    for phase in PHASES:
        ok(f"phase_{phase}", phase in src, phase)

    # --- Three-phase protocol functions ---
    ok("fn_request_cancel", "fn request_cancel" in src, "Phase 1: REQUEST")
    ok("fn_start_drain", "fn start_drain" in src, "Phase 2a: DRAIN start")
    ok("fn_complete_drain", "fn complete_drain" in src, "Phase 2b: DRAIN complete")
    ok("fn_finalize", "fn finalize" in src, "Phase 3: FINALIZE")

    # --- Drain configuration ---
    ok("drain_timeout_ms", "timeout_ms" in src, "Drain timeout config")
    ok("force_on_timeout", "force_on_timeout" in src, "Force finalize on timeout")
    ok("default_drain_timeout", "DEFAULT_DRAIN_TIMEOUT_MS" in src, "Default drain timeout constant")

    # --- Resource tracking ---
    ok("resource_tracker_clean", "fn is_clean" in src, "Resource tracker clean check")
    ok("resource_tracker_leaks", "fn leaked_resources" in src, "Resource leak detection")

    # --- Audit and export ---
    ok("audit_log", "fn export_audit_log_jsonl" in src, "JSONL audit export")
    ok("audit_event_schema", "schema_version" in src, "Audit event schema version")

    # --- Event codes ---
    ec = sum(1 for c in EVENT_CODES if c in src)
    ok("event_codes", ec >= 6, f"{ec}/6 event codes")

    # --- Error codes ---
    erc = sum(1 for c in ERROR_CODES if c in src)
    ok("error_codes", erc >= 4, f"{erc}/4 error codes")

    # --- Invariants ---
    inv = sum(1 for i in INVARIANTS if i in src)
    ok("invariants", inv >= 6, f"{inv}/6 invariants")

    # --- Schema version ---
    ok("schema_version", "cp-v1.0" in src, "cp-v1.0")

    # --- Idempotent cancel ---
    ok("idempotent_cancel", "CANP-IDEMPOTENT" in src and "idempotent" in src.lower(), "Idempotent cancel requests")

    # --- Lifecycle integration ---
    lifecycle_src = _read(LIFECYCLE)
    ok("lifecycle_cancelling_state", "Cancelling" in lifecycle_src, "Cancelling state in lifecycle FSM")
    ok("lifecycle_cancel_transition", "Cancelling" in lifecycle_src and "can_transition_to" in lifecycle_src, "Cancel transition in lifecycle")

    # --- Rollout state integration ---
    rollout_src = _read(ROLLOUT)
    ok("rollout_cancel_phase", "cancel_phase" in rollout_src, "CancelPhase field in RolloutState")
    ok("rollout_set_cancel", "fn set_cancel_phase" in rollout_src, "set_cancel_phase in RolloutState")
    ok("rollout_is_cancelling", "fn is_cancelling" in rollout_src, "is_cancelling in RolloutState")
    ok("rollout_imports_cancel", "cancellation_protocol" in rollout_src, "RolloutState imports cancellation_protocol")

    # --- Counts and accessors ---
    ok("fn_active_count", "fn active_count" in src, "Active cancellation count")
    ok("fn_finalized_count", "fn finalized_count" in src, "Finalized cancellation count")
    ok("fn_current_phase", "fn current_phase" in src, "Current phase accessor")
    ok("fn_get_record", "fn get_record" in src, "Get record accessor")

    # --- Timing report ---
    ok("fn_timing_report", "fn generate_timing_report" in src, "Timing report generation")

    # --- Cancellation readiness ---
    ok("fn_readiness_check", "fn cancellation_readiness_check" in src, "Cancellation readiness health check")

    # --- Test coverage ---
    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 20, f"{test_count} tests")

    # --- Timing CSV content ---
    if os.path.isfile(TIMING_CSV):
        csv_content = _read(TIMING_CSV)
        ok("timing_csv_header", "workflow_id" in csv_content and "phase" in csv_content, "CSV has required columns")
        ok("timing_csv_has_rows", len(csv_content.strip().split("\n")) >= 2, "CSV has data rows")
    else:
        ok("timing_csv_header", False, "CSV not found")
        ok("timing_csv_has_rows", False, "CSV not found")

    return r


def self_test():
    r = _checks()
    assert len(r) >= 40, f"Expected >= 40 checks, got {len(r)}"
    for x in r:
        assert "check" in x and "passed" in x and "detail" in x, f"Bad check format: {x}"
    print(f"self_test: {len(r)} checks OK", file=sys.stderr)
    return True


def main():
    as_json = "--json" in sys.argv
    if "--self-test" in sys.argv:
        self_test()
        return
    results = _checks()
    p = sum(1 for x in results if x["passed"])
    t = len(results)
    v = "PASS" if p == t else "FAIL"
    if as_json:
        print(json.dumps({
            "bead_id": BEAD,
            "section": SECTION,
            "gate_script": os.path.basename(__file__),
            "checks_passed": p,
            "checks_total": t,
            "verdict": v,
            "checks": results,
        }, indent=2))
    else:
        for x in results:
            print(f"  [{'PASS' if x['passed'] else 'FAIL'}] {x['check']}: {x['detail']}")
        print(f"\n{BEAD}: {p}/{t} checks — {v}")
    sys.exit(0 if v == "PASS" else 1)


if __name__ == "__main__":
    main()
