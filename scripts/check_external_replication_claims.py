#!/usr/bin/env python3
"""bd-e5cz: Externally replicated high-impact claims — verification gate."""
import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "external_replication_claims.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_16", "bd-e5cz_contract.md")
BEAD, SECTION = "bd-e5cz", "16"

CODES = [f"ERC-{str(i).zfill(3)}" for i in range(1, 11)] + ["ERC-ERR-001", "ERC-ERR-002"]
INVS = ["INV-ERC-CATEGORIZED", "INV-ERC-REPLICATED", "INV-ERC-DETERMINISTIC", "INV-ERC-GATED", "INV-ERC-VERSIONED", "INV-ERC-AUDITABLE"]

def _read(p):
    with open(p) as f: return f.read()

def _checks():
    r = []
    def ok(n, p, d=""): r.append({"check": n, "passed": p, "detail": d})
    src = _read(IMPL)
    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod external_replication_claims;" in _read(MOD_RS))
    ok("claim_categories", all(t in src for t in ["SecurityGuarantee", "PerformanceBenchmark", "ComplianceCertification", "ReliabilityMetric", "PrivacyAssurance"]), "5 categories")
    ok("replication_lifecycle", all(s in src for s in ["Requested", "InProgress", "Completed", "Verified"]), "4 statuses")
    for st in ["HighImpactClaim", "ReplicationRecord", "ClaimCatalog", "ExternalReplicationClaims"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)
    ok("replication_tracking", "replication_count" in src and "MIN_REPLICATIONS" in src, "Replication counting")
    ok("publication_gating", "can_publish" in src and "publish_claim" in src, "Threshold-gated publication")
    ok("evidence_linking", "link_evidence" in src and "evidence_refs" in src, "Evidence chain")
    ok("content_hash", "content_hash" in src and "Sha256" in src, "SHA-256 hashing")
    ok("event_codes", sum(1 for c in CODES if c in src) >= 12, f"{sum(1 for c in CODES if c in src)}/12")
    ok("invariants", sum(1 for i in INVS if i in src) >= 6, f"{sum(1 for i in INVS if i in src)}/6")
    ok("audit_log", "ErcAuditRecord" in src and "export_audit_log_jsonl" in src, "JSONL export")
    ok("schema_version", "erc-v1.0" in src, "erc-v1.0")
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
