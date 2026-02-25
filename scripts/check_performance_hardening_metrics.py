#!/usr/bin/env python3
"""bd-ka0n: Performance under hardening metrics — verification gate."""

import json
import os
import re
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools",
                     "performance_hardening_metrics.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_14", "bd-ka0n_contract.md")

BEAD = "bd-ka0n"
SECTION = "14"

REQUIRED_CATEGORIES = ["Startup", "Request", "Migration", "Verification", "Shutdown"]
REQUIRED_CODES = [f"PHM-{str(i).zfill(3)}" for i in range(1, 11)] + ["PHM-ERR-001", "PHM-ERR-002"]
REQUIRED_INVARIANTS = [
    "INV-PHM-PERCENTILE", "INV-PHM-DETERMINISTIC", "INV-PHM-OVERHEAD",
    "INV-PHM-GATED", "INV-PHM-VERSIONED", "INV-PHM-AUDITABLE",
]


def _read(p):
    with open(p) as f:
        return f.read()


def _checks():
    results = []
    def ok(name, passed, detail=""):
        results.append({"check": name, "passed": passed, "detail": detail})

    src = _read(IMPL)

    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod performance_hardening_metrics;" in _read(MOD_RS), "tools/mod.rs")

    found_cats = [c for c in REQUIRED_CATEGORIES if c in src]
    ok("operation_categories", len(found_cats) >= 5, f"{len(found_cats)}/5")

    ok("percentiles", "p50_ms" in src and "p95_ms" in src and "p99_ms" in src, "p50/p95/p99")
    ok("percentile_ordering", "is_ordered" in src, "Percentile ordering invariant")

    for st in ["PerformanceMetric", "Percentiles", "CategoryStats",
               "PerformanceReport", "PerformanceHardeningMetrics"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)

    ok("overhead_ratio", "overhead_ratio" in src, "Hardening overhead computation")
    ok("cold_start_ratio", "cold_start_ratio" in src, "Cold-start vs warm-start")
    ok("budget_enforcement", "budget_ms" in src and "within_budget" in src, "Category budgets")
    ok("flagged_categories", "flagged_categories" in src, "Budget violation flagging")

    found_codes = [c for c in REQUIRED_CODES if c in src]
    ok("event_codes", len(found_codes) >= 12, f"{len(found_codes)}/12")

    found_invs = [i for i in REQUIRED_INVARIANTS if i in src]
    ok("invariants", len(found_invs) >= 6, f"{len(found_invs)}/6")

    ok("audit_log", "PhmAuditRecord" in src and "export_audit_log_jsonl" in src, "JSONL export")
    ok("metric_version", "METRIC_VERSION" in src and "phm-v1.0" in src, "phm-v1.0")
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)

    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 24, f"{test_count} tests (>=24)")

    return results


def self_test():
    results = _checks()
    assert len(results) >= 15
    for r in results:
        assert "check" in r and "passed" in r
    print(f"self_test: {len(results)} checks OK", file=sys.stderr)
    return True


def main():
    logger = configure_test_logging("check_performance_hardening_metrics")
    as_json = "--json" in sys.argv
    if "--self-test" in sys.argv:
        self_test(); return

    results = _checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    verdict = "PASS" if passed == total else "FAIL"

    if as_json:
        print(json.dumps({
            "bead_id": BEAD, "section": SECTION,
            "gate_script": os.path.basename(__file__),
            "checks_passed": passed, "checks_total": total,
            "verdict": verdict, "checks": results,
        }, indent=2))
    else:
        for r in results:
            mark = "PASS" if r["passed"] else "FAIL"
            print(f"  [{mark}] {r['check']}: {r['detail']}")
        print(f"\n{BEAD}: {passed}/{total} checks — {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
