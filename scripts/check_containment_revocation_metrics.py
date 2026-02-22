#!/usr/bin/env python3
"""bd-2a6g: Containment/revocation latency metrics — verification gate.

Usage:
    python3 scripts/check_containment_revocation_metrics.py [--json]
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools",
                     "containment_revocation_metrics.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_14", "bd-2a6g_contract.md")

BEAD = "bd-2a6g"
SECTION = "14"

REQUIRED_CATEGORIES = [
    "Revocation", "Quarantine", "PolicyEnforcement",
    "TrustDowngrade", "EmergencyContainment",
]
REQUIRED_EVENT_CODES = [
    "CRM-001", "CRM-002", "CRM-003", "CRM-004", "CRM-005",
    "CRM-006", "CRM-007", "CRM-008", "CRM-009", "CRM-010",
    "CRM-ERR-001", "CRM-ERR-002",
]
REQUIRED_INVARIANTS = [
    "INV-CRM-PERCENTILE", "INV-CRM-CONVERGENCE", "INV-CRM-DETERMINISTIC",
    "INV-CRM-GATED", "INV-CRM-VERSIONED", "INV-CRM-AUDITABLE",
]


def _read(path):
    with open(path) as f:
        return f.read()


def _checks():
    results = []

    def ok(name, passed, detail=""):
        results.append({"check": name, "passed": passed, "detail": detail})

    src = _read(IMPL)

    # 1. Source exists
    ok("source_exists", os.path.isfile(IMPL), IMPL)

    # 2. Module wiring
    mod_src = _read(MOD_RS)
    ok("module_wiring",
       "pub mod containment_revocation_metrics;" in mod_src,
       "tools/mod.rs")

    # 3. Event categories (5)
    found_cats = [c for c in REQUIRED_CATEGORIES if c in src]
    ok("event_categories",
       len(found_cats) >= 5,
       f"{len(found_cats)}/5 categories")

    # 4. Core structs
    for st in ["Percentiles", "ContainmentEvent", "CategoryMetrics",
               "ContainmentReport", "CrmAuditRecord", "ContainmentRevocationMetrics"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)

    # 5. Percentile ordering
    ok("percentile_ordering",
       "p50_ms" in src and "p95_ms" in src and "p99_ms" in src and "is_ordered" in src,
       "p50 <= p95 <= p99 validation")

    # 6. Convergence measurement
    ok("convergence_measurement",
       "convergence_ratio" in src and "nodes_converged" in src and "nodes_total" in src,
       "Node convergence tracking")

    # 7. SLO gating
    ok("slo_gating",
       "slo_ms" in src and "exceeds_slo" in src,
       "Per-category SLO thresholds")

    # 8. Report generation
    ok("report_generation",
       "generate_report" in src and "ContainmentReport" in src,
       "Aggregated report with flagged categories")

    # 9. Metric versioning
    ok("metric_versioning",
       "METRIC_VERSION" in src and "crm-v1.0" in src,
       "crm-v1.0")

    # 10. Event codes (12)
    found_codes = [c for c in REQUIRED_EVENT_CODES if c in src]
    ok("event_codes",
       len(found_codes) >= 12,
       f"{len(found_codes)}/12 codes")

    # 11. Invariants (6)
    found_invs = [i for i in REQUIRED_INVARIANTS if i in src]
    ok("invariants",
       len(found_invs) >= 6,
       f"{len(found_invs)}/6 invariants")

    # 12. Audit log
    ok("audit_log",
       "CrmAuditRecord" in src and "export_audit_log_jsonl" in src,
       "JSONL audit export")

    # 13. Spec alignment
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)

    # 14. Test coverage
    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage",
       test_count >= 24,
       f"{test_count} tests (>=24)")

    return results


def self_test():
    """Smoke-test that all checks produce output."""
    results = _checks()
    assert len(results) >= 15, f"Expected >=15 checks, got {len(results)}"
    for r in results:
        assert "check" in r and "passed" in r
    print(f"self_test: {len(results)} checks OK", file=sys.stderr)
    return True


def main():
    as_json = "--json" in sys.argv

    if "--self-test" in sys.argv:
        self_test()
        return

    results = _checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    verdict = "PASS" if passed == total else "FAIL"

    if as_json:
        print(json.dumps({
            "bead_id": BEAD,
            "section": SECTION,
            "gate_script": os.path.basename(__file__),
            "checks_passed": passed,
            "checks_total": total,
            "verdict": verdict,
            "checks": results,
        }, indent=2))
    else:
        for r in results:
            mark = "PASS" if r["passed"] else "FAIL"
            print(f"  [{mark}] {r['check']}: {r['detail']}")
        print(f"\n{BEAD}: {passed}/{total} checks — {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
