#!/usr/bin/env python3
"""bd-18ie: Compatibility correctness metrics — verification gate."""

import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools",
                     "compatibility_correctness_metrics.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_14", "bd-18ie_contract.md")

BEAD = "bd-18ie"
SECTION = "14"

REQUIRED_API_FAMILIES = ["Core", "Extension", "Management", "Telemetry", "Migration"]
REQUIRED_RISK_BANDS = ["Critical", "High", "Medium", "Low"]
REQUIRED_CODES = [f"CCM-{str(i).zfill(3)}" for i in range(1, 11)] + ["CCM-ERR-001", "CCM-ERR-002"]
REQUIRED_INVARIANTS = [
    "INV-CCM-SEGMENTED", "INV-CCM-DETERMINISTIC", "INV-CCM-GATED",
    "INV-CCM-REGRESSION", "INV-CCM-VERSIONED", "INV-CCM-AUDITABLE",
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
    ok("module_wiring", "pub mod compatibility_correctness_metrics;" in _read(MOD_RS), "tools/mod.rs")

    found_fam = [f for f in REQUIRED_API_FAMILIES if f in src]
    ok("api_families", len(found_fam) >= 5, f"{len(found_fam)}/5")

    found_bands = [b for b in REQUIRED_RISK_BANDS if b in src]
    ok("risk_bands", len(found_bands) >= 4, f"{len(found_bands)}/4")

    ok("thresholds_defined",
       "0.999" in src and "0.995" in src and "0.99" in src and "0.95" in src,
       "Critical=99.9%, High=99.5%, Medium=99%, Low=95%")

    for st in ["CorrectnessMetric", "SegmentKey", "SegmentStats",
               "CorrectnessReport", "CompatibilityCorrectnessMetrics"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)

    ok("correctness_rate", "correctness_rate" in src and "meets_threshold" in src,
       "Rate computation + threshold check")

    ok("regression_detection", "CCM_REGRESSION_DETECTED" in src and "regressions" in src,
       "Regression event logging")

    ok("report_generation", "generate_report" in src and "CorrectnessReport" in src,
       "Aggregated report with segments")

    ok("flagged_segments", "flagged_segments" in src, "Below-threshold segment flagging")

    found_codes = [c for c in REQUIRED_CODES if c in src]
    ok("event_codes", len(found_codes) >= 12, f"{len(found_codes)}/12")

    found_invs = [i for i in REQUIRED_INVARIANTS if i in src]
    ok("invariants", len(found_invs) >= 6, f"{len(found_invs)}/6")

    ok("audit_log", "CcmAuditRecord" in src and "export_audit_log_jsonl" in src, "JSONL export")
    ok("metric_version", "METRIC_VERSION" in src and "ccm-v1.0" in src, "ccm-v1.0")
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)

    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 24, f"{test_count} tests (>=24)")

    return results


def self_test():
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
