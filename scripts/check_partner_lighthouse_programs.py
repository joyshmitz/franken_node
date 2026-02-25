#!/usr/bin/env python3
"""bd-31tg: Partner and lighthouse programs — verification gate."""
import json
import os
import re
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "partner_lighthouse_programs.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_15", "bd-31tg_contract.md")
BEAD, SECTION = "bd-31tg", "15"

CODES = [f"PLP-{str(i).zfill(3)}" for i in range(1, 11)] + ["PLP-ERR-001", "PLP-ERR-002"]
INVS = ["INV-PLP-TIERED", "INV-PLP-TRACKED", "INV-PLP-DETERMINISTIC", "INV-PLP-GATED", "INV-PLP-VERSIONED", "INV-PLP-AUDITABLE"]

def _read(p):
    with open(p) as f: return f.read()

def _checks():
    r = []
    def ok(n, p, d=""): r.append({"check": n, "passed": p, "detail": d})
    src = _read(IMPL)
    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod partner_lighthouse_programs;" in _read(MOD_RS))
    ok("partner_tiers", all(t in src for t in ["Prospect", "Pilot", "Lighthouse", "Strategic", "Flagship"]), "5 tiers")
    for st in ["Partner", "LighthouseDeployment", "OutcomeRecord", "AdoptionFunnel", "PartnerLighthousePrograms"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)
    ok("tier_promotion", "promote_partner" in src and "MIN_OUTCOMES_FOR_PROMOTION" in src, "Gated promotion")
    ok("deployment_tracking", "create_deployment" in src and "deployment_count" in src, "Deployment tracking")
    ok("outcome_recording", "record_outcome" in src and "outcome_count" in src, "Outcome metrics")
    ok("funnel_analytics", "generate_funnel" in src and "partners_by_tier" in src, "Adoption funnel")
    ok("content_hash", "content_hash" in src and "Sha256" in src, "SHA-256 hashing")
    ok("event_codes", sum(1 for c in CODES if c in src) >= 12, f"{sum(1 for c in CODES if c in src)}/12")
    ok("invariants", sum(1 for i in INVS if i in src) >= 6, f"{sum(1 for i in INVS if i in src)}/6")
    ok("audit_log", "PlpAuditRecord" in src and "export_audit_log_jsonl" in src, "JSONL export")
    ok("schema_version", "plp-v1.0" in src, "plp-v1.0")
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
    logger = configure_test_logging("check_partner_lighthouse_programs")
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
