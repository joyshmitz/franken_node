#!/usr/bin/env python3
"""bd-1961: Reputation graph APIs — verification gate."""
import json, os, re, sys
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "reputation_graph_apis.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_15", "bd-1961_contract.md")
BEAD, SECTION = "bd-1961", "15"

CODES = [f"RGA-{str(i).zfill(3)}" for i in range(1, 11)] + ["RGA-ERR-001", "RGA-ERR-002"]
INVS = ["INV-RGA-TYPED", "INV-RGA-WEIGHTED", "INV-RGA-DETERMINISTIC", "INV-RGA-GATED", "INV-RGA-VERSIONED", "INV-RGA-AUDITABLE"]

def _read(p):
    with open(p) as f: return f.read()

def _checks():
    r = []
    def ok(n, p, d=""): r.append({"check": n, "passed": p, "detail": d})
    src = _read(IMPL)
    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod reputation_graph_apis;" in _read(MOD_RS))
    ok("node_types", all(t in src for t in ["Operator", "Extension", "Verifier", "DataSource", "Infrastructure"]), "5 types")
    for st in ["ReputationNode", "ReputationEdge", "ReputationScore", "GraphSnapshot", "ReputationGraphApis"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)
    ok("edge_weight", "weight" in src and "evidence" in src, "Weighted edges with evidence")
    ok("composite_score", "composite_score" in src and "MIN_TRUST_SCORE" in src, "Scoring with threshold")
    ok("graph_queries", "neighbors" in src and "subgraph" in src, "Query operations")
    ok("decay_support", "apply_decay" in src and "DECAY_FACTOR" in src, "Score decay")
    ok("content_hash", "content_hash" in src and "Sha256" in src, "SHA-256 hashing")
    ok("event_codes", sum(1 for c in CODES if c in src) >= 12, f"{sum(1 for c in CODES if c in src)}/12")
    ok("invariants", sum(1 for i in INVS if i in src) >= 6, f"{sum(1 for i in INVS if i in src)}/6")
    ok("audit_log", "RgaAuditRecord" in src and "export_audit_log_jsonl" in src, "JSONL export")
    ok("schema_version", "rga-v1.0" in src, "rga-v1.0")
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
    logger = configure_test_logging("check_reputation_graph_apis")
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
