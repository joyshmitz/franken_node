#!/usr/bin/env python3
"""bd-2qqu: Verify virtual transport fault harness implementation."""
import json
import os
import re
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
SRC = os.path.join(ROOT, "crates", "franken-node", "src", "remote", "virtual_transport_faults.rs")

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

    events = ["FAULT_INJECTED","FAULT_SCHEDULE_CREATED","FAULT_CAMPAIGN_COMPLETE","FAULT_LOG_EXPORTED",
              "FAULT_DROP_APPLIED","FAULT_REORDER_APPLIED","FAULT_CORRUPT_APPLIED","FAULT_NONE",
              "FAULT_HARNESS_INIT","FAULT_SCENARIO_START","FAULT_SCENARIO_END","FAULT_AUDIT_EMITTED"]
    missing = [e for e in events if e not in src]
    check("EVENT_CODES", len(missing)==0, f"{len(events)-len(missing)}/{len(events)} event codes")

    invs = ["INV-VTF-DETERMINISTIC","INV-VTF-DROP","INV-VTF-REORDER","INV-VTF-CORRUPT","INV-VTF-LOGGED","INV-VTF-REPRODUCIBLE"]
    missing_inv = [i for i in invs if i not in src]
    check("INVARIANTS", len(missing_inv)==0, f"{len(invs)-len(missing_inv)}/{len(invs)} invariants")

    types = ["VirtualTransportFaultHarness","FaultClass","FaultConfig","FaultSchedule","CampaignResult"]
    missing_t = [t for t in types if t not in src]
    check("CORE_TYPES", len(missing_t)==0, f"{len(types)-len(missing_t)}/{len(types)} types")

    scenarios = ["no_faults","moderate_drops","heavy_reorder","light_corruption","chaos"]
    missing_s = [s for s in scenarios if f"pub fn {s}()" not in src]
    check("PREBUILT_SCENARIOS", len(missing_s)==0, f"{len(scenarios)-len(missing_s)}/{len(scenarios)} scenarios")

    check("DETERMINISTIC_SCHEDULE", "from_seed" in src and "xorshift" in src.lower(), "seed-based deterministic schedule")
    check("FAULT_INJECTION", "apply_drop" in src and "apply_reorder" in src and "apply_corrupt" in src, "3 fault injection methods")
    check("CAMPAIGN_RUNNER", "run_campaign" in src and "CampaignResult" in src, "campaign execution")
    check("AUDIT_TRAIL", "export_fault_log_jsonl" in src and "export_audit_log_jsonl" in src, "log export")

    test_count = len(re.findall(r'#\[test\]', src))
    check("TEST_COVERAGE", test_count >= 12, f"{test_count} tests found")

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
    logger = configure_test_logging("check_virtual_transport_faults")
    if "--self-test" in sys.argv:
        ok = self_test()
        sys.exit(0 if ok else 1)
    results = _checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    verdict = "PASS" if passed == total else "FAIL"
    report = {"bead": "bd-2qqu", "title": "Virtual Transport Fault Harness", "verdict": verdict,
              "passed": passed, "total": total, "checks": results}
    if "--json" in sys.argv:
        print(json.dumps(report, indent=2))
    else:
        print(f"bd-2qqu virtual_transport_faults: {verdict} ({passed}/{total})")
        for r in results:
            status = "PASS" if r["passed"] else "FAIL"
            print(f"  [{status}] {r['check']}: {r['detail']}")
    sys.exit(0 if verdict == "PASS" else 1)

if __name__ == "__main__":
    main()
