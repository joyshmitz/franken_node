#!/usr/bin/env python3
"""bd-sxt5: Migration validation cohorts — verification gate."""
import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "migration_validation_cohorts.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_15", "bd-sxt5_contract.md")
BEAD, SECTION = "bd-sxt5", "15"

CODES = [f"MVC-{str(i).zfill(3)}" for i in range(1, 11)] + ["MVC-ERR-001", "MVC-ERR-002"]
INVS = ["INV-MVC-COHORTED", "INV-MVC-DETERMINISTIC", "INV-MVC-REPRODUCIBLE", "INV-MVC-GATED", "INV-MVC-VERSIONED", "INV-MVC-AUDITABLE"]

def _read(p):
    with open(p) as f: return f.read()

def _checks():
    r = []
    def ok(n, p, d=""): r.append({"check": n, "passed": p, "detail": d})
    src = _read(IMPL)
    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod migration_validation_cohorts;" in _read(MOD_RS))
    ok("cohort_categories", all(t in src for t in ["NodeMinimal", "NodeComplex", "BunMinimal", "BunComplex", "Polyglot"]), "5 categories")
    for st in ["ProjectCohort", "ValidationRun", "CohortReport", "MigrationValidationCohorts"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)
    ok("determinism_check", "deterministic" in src and "MIN_DETERMINISM_RATE" in src, "Determinism validation")
    ok("reproduction_command", "reproduction_command" in src, "Reproduction steps")
    ok("drift_detection", "DRIFT_DETECTED" in src or "drift" in src.lower(), "Drift detection")
    ok("coverage_analysis", "coverage_by_category" in src, "Category coverage")
    ok("content_hash", "content_hash" in src and "Sha256" in src, "SHA-256 hashing")
    ok("event_codes", sum(1 for c in CODES if c in src) >= 12, f"{sum(1 for c in CODES if c in src)}/12")
    ok("invariants", sum(1 for i in INVS if i in src) >= 6, f"{sum(1 for i in INVS if i in src)}/6")
    ok("audit_log", "MvcAuditRecord" in src and "export_audit_log_jsonl" in src, "JSONL export")
    ok("schema_version", "mvc-v1.0" in src, "mvc-v1.0")
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
