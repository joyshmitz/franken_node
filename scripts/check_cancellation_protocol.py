#!/usr/bin/env python3
"""bd-1cs7: Three-phase cancellation protocol (REQUEST -> DRAIN -> FINALIZE) — verification gate."""
import json, os, re, sys
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "connector", "cancellation_protocol.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "connector", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_10_15", "bd-1cs7_contract.md")
TIMING_CSV = os.path.join(ROOT, "artifacts", "10.15", "cancel_protocol_timing.csv")
CONFORMANCE = os.path.join(ROOT, "tests", "conformance", "cancel_drain_finalize.rs")
EVIDENCE = os.path.join(ROOT, "artifacts", "section_10_15", "bd-1cs7", "verification_evidence.json")
SUMMARY = os.path.join(ROOT, "artifacts", "section_10_15", "bd-1cs7", "verification_summary.md")
LIFECYCLE = os.path.join(ROOT, "crates", "franken-node", "src", "connector", "lifecycle.rs")
ROLLOUT = os.path.join(ROOT, "crates", "franken-node", "src", "connector", "rollout_state.rs")
BEAD, SECTION = "bd-1cs7", "10.15"

EVENT_CODES = ["CAN-001", "CAN-002", "CAN-003", "CAN-004", "CAN-005", "CAN-006"]
ERROR_CODES = [
    "ERR_CANCEL_INVALID_PHASE", "ERR_CANCEL_ALREADY_FINAL",
    "ERR_CANCEL_DRAIN_TIMEOUT", "ERR_CANCEL_LEAK",
]
INVARIANTS = [
    "INV-CAN-THREE-PHASE", "INV-CAN-BUDGET-BOUNDED",
    "INV-CAN-PROPAGATION", "INV-CAN-NO-LEAK",
]
PHASES = ["Idle", "Requested", "Draining", "Finalizing", "Completed"]
WORKFLOWS = ["Lifecycle", "Rollout", "Publish", "Revoke", "Quarantine", "Migration"]

def _read(p):
    if not os.path.isfile(p):
        return ""
    with open(p) as f: return f.read()

def _checks():
    r = []
    def ok(n, p, d=""): r.append({"check": n, "passed": p, "detail": d})
    src = _read(IMPL)

    # ── File existence ────────────────────────────────────────────────
    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod cancellation_protocol;" in _read(MOD_RS))
    ok("spec_contract_exists", os.path.isfile(SPEC), SPEC)
    ok("conformance_test_exists", os.path.isfile(CONFORMANCE), CONFORMANCE)
    ok("timing_csv_exists", os.path.isfile(TIMING_CSV), TIMING_CSV)
    ok("evidence_exists", os.path.isfile(EVIDENCE), EVIDENCE)
    ok("summary_exists", os.path.isfile(SUMMARY), SUMMARY)

    # ── Phase enum (CancellationPhase) ────────────────────────────────
    for phase in PHASES:
        ok(f"phase_{phase}", phase in src and "CancellationPhase" in src, phase)

    # ── Core types ────────────────────────────────────────────────────
    for st in ["CancellationPhase", "CancellationBudget", "CancellationProtocol",
               "CancellationAuditEvent", "ResourceTracker", "ResourceGuard",
               "PhaseTransitionResult", "TimingRow", "WorkflowKind"]:
        found = ("struct " + st in src or "enum " + st in src
                 or "pub struct " + st in src or "pub enum " + st in src)
        ok(f"type_{st}", found, st)

    # ── Workflow coverage ─────────────────────────────────────────────
    wf_count = sum(1 for w in WORKFLOWS if w in src)
    ok("workflow_coverage", wf_count >= 6, f"{wf_count}/6 workflows")

    # ── Core operations ───────────────────────────────────────────────
    ok("fn_request", "fn request" in src, "REQUEST phase")
    ok("fn_drain", "fn drain" in src, "DRAIN phase")
    ok("fn_finalize", "fn finalize" in src, "FINALIZE phase")
    ok("fn_run_full", "fn run_full" in src, "Full three-phase execution")
    ok("fn_force_finalize", "fn force_finalize" in src, "Force-finalize")

    # ── Budget features ───────────────────────────────────────────────
    ok("budget_timeout_ms", "timeout_ms" in src, "Per-workflow timeout field")
    ok("budget_is_exceeded", "fn is_exceeded" in src, "Budget exceeded check")
    ok("budget_from_kind", "fn from_kind" in src, "Budget from WorkflowKind")

    # ── Resource tracking ─────────────────────────────────────────────
    ok("resource_acquire", "fn acquire" in src, "Resource acquisition")
    ok("resource_release", "fn release" in src, "Resource release")
    ok("resource_has_leaks", "fn has_leaks" in src, "Leak detection")
    ok("resource_release_all", "fn release_all" in src, "Bulk resource release")

    # ── Drop safety ───────────────────────────────────────────────────
    ok("drop_safety", "impl Drop for ResourceGuard" in src, "Drop safety")

    # ── Child propagation (INV-CAN-PROPAGATION) ──────────────────────
    ok("fn_register_child", "fn register_child" in src, "Child registration")
    ok("fn_complete_child", "fn complete_child" in src, "Child completion")

    # ── Audit features ────────────────────────────────────────────────
    ok("audit_log", "fn export_audit_log_jsonl" in src, "JSONL audit export")

    # ── Timing CSV ────────────────────────────────────────────────────
    ok("fn_generate_timing_csv", "fn generate_timing_csv" in src, "Timing CSV generation")

    # ── Event codes ───────────────────────────────────────────────────
    ec = sum(1 for c in EVENT_CODES if c in src)
    ok("event_codes", ec >= 6, f"{ec}/6")

    # ── Error codes ───────────────────────────────────────────────────
    erc = sum(1 for c in ERROR_CODES if c in src)
    ok("error_codes", erc >= 4, f"{erc}/4")

    # ── Invariants ────────────────────────────────────────────────────
    inv = sum(1 for i in INVARIANTS if i in src)
    ok("invariants", inv >= 4, f"{inv}/4")

    # ── Schema version ────────────────────────────────────────────────
    ok("schema_version", "cancel-v1.0" in src, "cancel-v1.0")

    # ── Bead ID ───────────────────────────────────────────────────────
    ok("bead_id", "bd-1cs7" in src, "bd-1cs7")

    # ── Integration: lifecycle.rs ─────────────────────────────────────
    lc = _read(LIFECYCLE)
    ok("lifecycle_cancelling_state", "Cancelling" in lc, "Cancelling state in lifecycle")
    ok("lifecycle_cancel_transition", "cancelling" in lc.lower(), "Cancel transition wiring")

    # ── Integration: rollout_state.rs ─────────────────────────────────
    rs = _read(ROLLOUT)
    ok("rollout_cancel_phase", "cancel_phase" in rs, "cancel_phase field in rollout")
    ok("rollout_set_cancel", "fn set_cancel_phase" in rs, "set_cancel_phase method")
    ok("rollout_is_cancelling", "fn is_cancelling" in rs, "is_cancelling method")
    ok("rollout_imports_cancel", "CancellationPhase" in rs, "imports CancellationPhase")

    # ── Test coverage ─────────────────────────────────────────────────
    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 15, f"{test_count} tests")

    # ── Timing CSV content ────────────────────────────────────────────
    if os.path.isfile(TIMING_CSV):
        csv = _read(TIMING_CSV)
        ok("timing_csv_header", "workflow_id,phase,budget_ms" in csv, "CSV header")
        csv_lines = [l for l in csv.strip().split("\n") if l and not l.startswith("workflow_id")]
        ok("timing_csv_has_rows", len(csv_lines) >= 6, f"{len(csv_lines)} data rows")
    else:
        ok("timing_csv_header", False, "timing CSV missing")
        ok("timing_csv_has_rows", False, "timing CSV missing")

    # ── Spec contract sections ────────────────────────────────────────
    spec_content = _read(SPEC)
    for section in ["Invariants", "Event Codes", "Error Codes", "Acceptance Criteria",
                    "Three-Phase Protocol", "Gate Behavior"]:
        ok(f"spec_{section.lower().replace(' ', '_').replace('-', '_')}", section in spec_content, section)

    return r

def self_test():
    r = _checks()
    assert len(r) >= 40
    for x in r:
        assert "check" in x and "passed" in x
    print(f"self_test: {len(r)} checks OK", file=sys.stderr)
    return True

def main():
    logger = configure_test_logging("check_cancellation_protocol")
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
