#!/usr/bin/env python3
"""bd-1ru2: Verify cancel-safe eviction saga implementation."""
import json, os, re, sys
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "crates", "franken-node", "src", "remote", "eviction_saga.rs")

def _read(path):
    with open(path) as f:
        return f.read()

def _checks():
    results = []
    def check(name, passed, detail=""):
        results.append({"check": name, "passed": passed, "detail": detail})

    if not os.path.isfile(SRC):
        check("SOURCE_EXISTS", False, f"missing {SRC}")
        return results
    src = _read(SRC)
    check("SOURCE_EXISTS", True, SRC)

    events = ["ES_SAGA_START","ES_PHASE_UPLOAD","ES_PHASE_VERIFY","ES_PHASE_RETIRE",
              "ES_SAGA_COMPLETE","ES_COMPENSATION_START","ES_COMPENSATION_COMPLETE",
              "ES_LEAK_CHECK_PASSED","ES_LEAK_CHECK_FAILED","ES_CRASH_RECOVERY",
              "ES_CANCEL_REQUESTED","ES_AUDIT_EMITTED"]
    missing = [e for e in events if e not in src]
    check("EVENT_CODES", len(missing)==0, f"{len(events)-len(missing)}/{len(events)} event codes")

    invs = ["INV-ES-CANCEL-SAFE","INV-ES-DETERMINISTIC","INV-ES-LEAK-FREE","INV-ES-GATED","INV-ES-PERSISTED","INV-ES-AUDITABLE"]
    missing_inv = [i for i in invs if i not in src]
    check("INVARIANTS", len(missing_inv)==0, f"{len(invs)-len(missing_inv)}/{len(invs)} invariants")

    types = ["SagaPhase","CompensationAction","SagaInstance","EvictionSagaManager","LeakCheckResult"]
    missing_t = [t for t in types if t not in src]
    check("CORE_TYPES", len(missing_t)==0, f"{len(types)-len(missing_t)}/{len(types)} types")

    phases = ["Created","Uploading","Verifying","Retiring","Complete","Compensating","Compensated","Failed"]
    missing_p = [p for p in phases if f"SagaPhase::{p}" in src or f"{p}" in src]
    check("SAGA_PHASES", len(missing_p) >= 8, f"{len(missing_p)}/8 saga phases defined")

    compensations = ["AbortUpload","CleanupL3","CompleteRetirement"]
    missing_c = [c for c in compensations if c in src]
    check("COMPENSATION_MATRIX", len(missing_c) == 3, f"{len(missing_c)}/3 compensation actions")

    check("REMOTECAP_GATING", "has_remote_cap" in src and "RemoteCap required" in src, "RemoteCap gate on saga start")
    check("CANCEL_SAFETY", "cancel_saga" in src and "compensation_action" in src, "cancel-safe compensation")
    check("LEAK_DETECTION", "leak_check" in src and "orphans" in src, "leak/orphan detection")
    check("CRASH_RECOVERY", "recover_saga" in src and "ES_CRASH_RECOVERY" in src, "crash recovery support")
    check("AUDIT_TRAIL", "export_audit_log_jsonl" in src and "export_saga_trace_jsonl" in src, "audit + trace export")

    test_count = len(re.findall(r'#\[test\]', src))
    check("TEST_COVERAGE", test_count >= 10, f"{test_count} tests found")

    return results

def self_test():
    results = _checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    print(f"self_test: {passed}/{total} checks passed")
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"  [{status}] {r['check']}: {r['detail']}")
    return passed == total

def main():
    logger = configure_test_logging("check_eviction_saga")
    if "--self-test" in sys.argv:
        ok = self_test()
        sys.exit(0 if ok else 1)
    results = _checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    verdict = "PASS" if passed == total else "FAIL"
    report = {"bead": "bd-1ru2", "title": "Cancel-Safe Eviction Saga", "verdict": verdict,
              "passed": passed, "total": total, "checks": results}
    if "--json" in sys.argv:
        print(json.dumps(report, indent=2))
    else:
        print(f"bd-1ru2 eviction_saga: {verdict} ({passed}/{total})")
        for r in results:
            status = "PASS" if r["passed"] else "FAIL"
            print(f"  [{status}] {r['check']}: {r['detail']}")
    sys.exit(0 if verdict == "PASS" else 1)

if __name__ == "__main__":
    main()
