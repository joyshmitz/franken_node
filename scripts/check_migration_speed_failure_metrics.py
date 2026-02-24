#!/usr/bin/env python3
"""bd-2fkq: Migration speed and failure-rate metrics — verification gate."""
import json, os, re, sys
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "migration_speed_failure_metrics.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_14", "bd-2fkq_contract.md")
BEAD, SECTION = "bd-2fkq", "14"

CODES = [f"MSF-{str(i).zfill(3)}" for i in range(1, 11)] + ["MSF-ERR-001", "MSF-ERR-002"]
INVS = ["INV-MSF-PHASED", "INV-MSF-CATEGORIZED", "INV-MSF-DETERMINISTIC", "INV-MSF-GATED", "INV-MSF-VERSIONED", "INV-MSF-AUDITABLE"]

def _read(p):
    with open(p) as f: return f.read()

def _checks():
    r = []
    def ok(n, p, d=""): r.append({"check": n, "passed": p, "detail": d})
    src = _read(IMPL)
    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod migration_speed_failure_metrics;" in _read(MOD_RS))
    ok("migration_phases", all(t in src for t in ["Assessment", "DependencyResolution", "CodeAdaptation", "TestValidation", "Deployment"]), "5 phases")
    ok("failure_types", all(t in src for t in ["DependencyConflict", "ApiIncompatibility", "RuntimeError", "TestRegression", "ConfigurationError"]), "5 types")
    for st in ["MigrationRecord", "PhaseStats", "FailureStats", "MigrationSpeedReport", "MigrationSpeedFailureMetrics"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)
    ok("phase_durations", "PhaseDuration" in src and "duration_ms" in src, "Per-phase timing")
    ok("failure_rate", "failure_rate" in src and "MAX_FAILURE_RATE" in src, "Rate with threshold")
    ok("speed_computation", "avg_total_duration_ms" in src and "p90_duration_ms" in src, "Avg + p90")
    ok("threshold_gating", "exceeds_threshold" in src and "MAX_FAILURE_RATE" in src, "Threshold enforcement")
    ok("content_hash", "content_hash" in src and "Sha256" in src, "SHA-256 hashing")
    ok("event_codes", sum(1 for c in CODES if c in src) >= 12, f"{sum(1 for c in CODES if c in src)}/12")
    ok("invariants", sum(1 for i in INVS if i in src) >= 6, f"{sum(1 for i in INVS if i in src)}/6")
    ok("audit_log", "MsfAuditRecord" in src and "export_audit_log_jsonl" in src, "JSONL export")
    ok("metric_version", "msf-v1.0" in src, "msf-v1.0")
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)
    ok("test_coverage", len(re.findall(r"#\[test\]", src)) >= 22, f"{len(re.findall(r'#[test]', src))} tests")
    return r

def self_test():
    r = _checks()
    assert len(r) >= 16
    for x in r:
        assert "check" in x and "passed" in x
    print(f"self_test: {len(r)} checks OK", file=sys.stderr)
    return True

def main():
    logger = configure_test_logging("check_migration_speed_failure_metrics")
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
