#!/usr/bin/env python3
"""bd-18ie gate: Compatibility Correctness Metric Family (Section 14).

Validates the Rust implementation in
crates/franken-node/src/tools/compatibility_correctness_metrics.rs against
the spec contract docs/specs/section_14/bd-18ie_contract.md.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

SRC = ROOT / "crates" / "franken-node" / "src" / "tools" / "compatibility_correctness_metrics.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "tools" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_14" / "bd-18ie_contract.md"

BEAD = "bd-18ie"
SECTION = "14"

API_FAMILIES = ["Core", "Extension", "Management", "Telemetry", "Migration"]

RISK_BANDS = ["Critical", "High", "Medium", "Low"]

EVENT_CODES = [
    "CCM-001", "CCM-002", "CCM-003", "CCM-004", "CCM-005",
    "CCM-006", "CCM-007", "CCM-008", "CCM-009", "CCM-010",
    "CCM-ERR-001", "CCM-ERR-002",
]

INVARIANTS = [
    "INV-CCM-SEGMENTED",
    "INV-CCM-DETERMINISTIC",
    "INV-CCM-GATED",
    "INV-CCM-REGRESSION",
    "INV-CCM-VERSIONED",
    "INV-CCM-AUDITABLE",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _checks():
    results = []

    def ok(name, passed, detail=""):
        results.append({"check": name, "passed": passed, "detail": detail})

    src = _read(SRC)

    # 1. Source exists
    ok("source_exists", SRC.is_file(), SRC.name)

    # 2. Module wiring
    mod_src = _read(MOD_RS)
    ok("module_wiring",
       "pub mod compatibility_correctness_metrics;" in mod_src,
       "tools/mod.rs")

    # 3. API families (5)
    found_families = [f for f in API_FAMILIES if f in src]
    ok("api_families", len(found_families) >= 5, f"{len(found_families)}/5 families")

    # 4. Risk bands (4)
    found_bands = [b for b in RISK_BANDS if b in src]
    ok("risk_bands", len(found_bands) >= 4, f"{len(found_bands)}/4 bands")

    # 5. Structs
    for st in ["CorrectnessMetric", "SegmentKey", "SegmentStats",
               "CorrectnessReport", "CcmAuditRecord", "CompatibilityCorrectnessMetrics"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)

    # 6. Metric submission
    ok("metric_submission",
       "submit_metric" in src and "total_tests" in src and "passed_tests" in src,
       "Metric submission with validation")

    # 7. Report generation
    ok("report_generation",
       "generate_report" in src and "CorrectnessReport" in src and "content_hash" in src,
       "Report with segments and content hash")

    # 8. Threshold enforcement
    ok("threshold_enforcement",
       "threshold" in src and "meets_threshold" in src,
       "Per-band threshold gates")

    # 9. Regression detection
    ok("regression_detection",
       "regressions" in src and "REGRESSION_DETECTED" in src,
       "Regression detection and logging")

    # 10. Event codes (12)
    found_codes = [c for c in EVENT_CODES if c in src]
    ok("event_codes", len(found_codes) >= 12, f"{len(found_codes)}/12 codes")

    # 11. Invariants (6)
    found_invs = [i for i in INVARIANTS if i in src]
    ok("invariants", len(found_invs) >= 6, f"{len(found_invs)}/6 invariants")

    # 12. Audit log
    ok("audit_log",
       "CcmAuditRecord" in src and "export_audit_log_jsonl" in src,
       "JSONL audit export")

    # 13. Spec alignment
    ok("spec_alignment", SPEC.is_file(), str(SPEC.name))

    # 14. Version embedding
    ok("version_embedding",
       "METRIC_VERSION" in src and "ccm-v1.0" in src,
       "ccm-v1.0")

    # 15. Test coverage
    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 20, f"{test_count} tests (>=20)")

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
    logger = configure_test_logging("check_compatibility_correctness")
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
            "gate_script": "check_compatibility_correctness.py",
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
