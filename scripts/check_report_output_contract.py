#!/usr/bin/env python3
"""bd-1sgr: Report output contract — verification gate."""
import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "report_output_contract.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_16", "bd-1sgr_contract.md")
BEAD, SECTION = "bd-1sgr", "16"

CODES = [f"ROC-{str(i).zfill(3)}" for i in range(1, 11)] + ["ROC-ERR-001", "ROC-ERR-002"]
INVS = ["INV-ROC-COMPLETE", "INV-ROC-DETERMINISTIC", "INV-ROC-INTEGRITY", "INV-ROC-REPRODUCIBLE", "INV-ROC-VERSIONED", "INV-ROC-AUDITABLE"]

def _read(p):
    with open(p) as f: return f.read()

def _checks():
    r = []
    def ok(n, p, d=""): r.append({"check": n, "passed": p, "detail": d})
    src = _read(IMPL)
    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod report_output_contract;" in _read(MOD_RS))
    ok("report_types", all(t in src for t in ["TechnicalAnalysis", "SecurityAssessment", "PerformanceBenchmark", "ComplianceReport", "IncidentPostmortem"]), "5 types")
    ok("required_artifacts", "REQUIRED_ARTIFACT_TYPES" in src and "report_pdf" in src, "5 required artifact types")
    for st in ["ReportBundle", "ArtifactEntry", "OutputCatalog", "ReportOutputContract"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)
    ok("integrity_verification", "content_hash" in src and "Sha256" in src, "SHA-256 hashing")
    ok("completeness_checking", "is_complete" in src and "REQUIRED_ARTIFACT_TYPES" in src, "Completeness validation")
    ok("reproducibility", "reproduction_command" in src, "Reproduction instructions")
    ok("catalog_generation", "generate_catalog" in src and "OutputCatalog" in src, "Catalog with completeness")
    ok("event_codes", sum(1 for c in CODES if c in src) >= 12, f"{sum(1 for c in CODES if c in src)}/12")
    ok("invariants", sum(1 for i in INVS if i in src) >= 6, f"{sum(1 for i in INVS if i in src)}/6")
    ok("audit_log", "RocAuditRecord" in src and "export_audit_log_jsonl" in src, "JSONL export")
    ok("contract_version", "roc-v1.0" in src, "roc-v1.0")
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)
    ok("test_coverage", len(re.findall(r"#\[test\]", src)) >= 18, f"{len(re.findall(r'#[test]', src))} tests")
    return r

def self_test():
    r = _checks()
    assert len(r) >= 14
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
