#!/usr/bin/env python3
"""bd-876n: Cancellation injection for critical control workflows — verification gate."""
import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "control_plane", "cancellation_injection.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "control_plane", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_10_14", "bd-876n_contract.md")
BEAD, SECTION = "bd-876n", "10.14"

EVENT_CODES = [
    "CANCEL_INJECTED", "CANCEL_LEAK_CHECK", "CANCEL_HALFCOMMIT_CHECK",
    "CANCEL_MATRIX_COMPLETE", "CANCEL_WORKFLOW_START", "CANCEL_WORKFLOW_END",
    "CANCEL_RESOURCE_SNAPSHOT", "CANCEL_STATE_SNAPSHOT",
    "CANCEL_CASE_PASSED", "CANCEL_CASE_FAILED",
]
ERROR_CODES = [
    "ERR_CANCEL_LEAK_DETECTED", "ERR_CANCEL_HALFCOMMIT",
    "ERR_CANCEL_MATRIX_INCOMPLETE", "ERR_CANCEL_UNKNOWN_WORKFLOW",
    "ERR_CANCEL_INVALID_POINT", "ERR_CANCEL_FRAMEWORK_ERROR",
    "ERR_CANCEL_STATE_MISMATCH", "ERR_CANCEL_TIMEOUT",
]
INVS = [
    "INV-CANCEL-LEAK-FREE", "INV-CANCEL-HALFCOMMIT-FREE",
    "INV-CANCEL-MATRIX-COMPLETE", "INV-CANCEL-DETERMINISTIC",
    "INV-CANCEL-BARRIER-SAFE", "INV-CANCEL-SAGA-SAFE",
]
WORKFLOWS = [
    "EpochTransitionBarrier", "MarkerStreamAppend",
    "RootPointerPublication", "EvidenceCommit", "EvictionSaga",
]

def _read(p):
    with open(p) as f: return f.read()

def _checks():
    r = []
    def ok(n, p, d=""): r.append({"check": n, "passed": p, "detail": d})
    src = _read(IMPL)

    # File existence and module wiring
    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod cancellation_injection;" in _read(MOD_RS))

    # Core types
    for st in ["WorkflowId", "AwaitPoint", "ResourceSnapshot", "ResourceDelta",
               "StateSnapshot", "HalfCommitDetection", "CancelTestOutcome",
               "CancelMatrixEntry", "CancelInjectionMatrix", "CancelAuditRecord",
               "CancelError", "WorkflowRegistration", "CancellationInjectionFramework"]:
        ok(f"struct_{st}", st in src and ("struct " + st in src or "enum " + st in src or "pub struct " + st in src), st)

    # Workflows
    wf_count = sum(1 for w in WORKFLOWS if w in src)
    ok("workflow_coverage", wf_count >= 5, f"{wf_count}/5 workflows")

    # Core operations
    ok("fn_register_workflow", "fn register_workflow" in src, "Register workflow")
    ok("fn_run_cancel_case", "fn run_cancel_case" in src, "Run cancel case")
    ok("fn_register_default_workflows", "fn register_default_workflows" in src, "Register defaults")
    ok("fn_detect_halfcommit", "fn detect_halfcommit" in src, "Half-commit detection")
    ok("fn_has_leaks", "fn has_leaks" in src, "Leak detection")
    ok("fn_delta", "fn delta" in src, "Resource delta")

    # Matrix features
    ok("matrix_coverage", "fn meets_minimum_coverage" in src, "Minimum coverage check")
    ok("matrix_verdict", "fn verdict" in src, "Matrix verdict")
    ok("matrix_record_case", "fn record_case" in src, "Record case")
    ok("min_matrix_cases", "MIN_MATRIX_CASES" in src, "Min matrix cases constant")

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
    ok("schema_version", "ci-v1.0" in src, "ci-v1.0")

    # Spec alignment
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)

    # Test coverage
    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 20, f"{test_count} tests")

    return r

def self_test():
    r = _checks()
    assert len(r) >= 30
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
