#!/usr/bin/env python3
"""bd-33u2: Verifier/benchmark releases — verification gate."""
import json
import os
import re
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "verifier_benchmark_releases.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_16", "bd-33u2_contract.md")
BEAD, SECTION = "bd-33u2", "16"

CODES = [f"VBR-{str(i).zfill(3)}" for i in range(1, 11)] + ["VBR-ERR-001", "VBR-ERR-002"]
INVS = ["INV-VBR-TYPED", "INV-VBR-TRACKED", "INV-VBR-DETERMINISTIC", "INV-VBR-GATED", "INV-VBR-VERSIONED", "INV-VBR-AUDITABLE"]

def _read(p):
    with open(p) as f: return f.read()

def _checks():
    r = []
    def ok(n, p, d=""): r.append({"check": n, "passed": p, "detail": d})
    src = _read(IMPL)
    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod verifier_benchmark_releases;" in _read(MOD_RS))
    ok("release_types", all(t in src for t in ["VerifierTool", "BenchmarkSuite", "TestHarness", "ComplianceChecker", "DocumentationKit"]), "5 types")
    ok("release_lifecycle", all(s in src for s in ["Draft", "Published", "Deprecated", "Archived"]), "4 statuses")
    for st in ["ToolRelease", "ReleaseArtifact", "DownloadRecord", "AdoptionMetrics", "VerifierBenchmarkReleases"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)
    ok("download_tracking", "record_download" in src and "download_count" in src, "Download tracking")
    ok("quality_gating", "publish_release" in src and "MIN_QUALITY_SCORE" in src, "Quality threshold")
    ok("changelog_support", "update_changelog" in src and "changelog" in src, "Changelog management")
    ok("content_hash", "content_hash" in src and "Sha256" in src, "SHA-256 hashing")
    ok("event_codes", sum(1 for c in CODES if c in src) >= 12, f"{sum(1 for c in CODES if c in src)}/12")
    ok("invariants", sum(1 for i in INVS if i in src) >= 6, f"{sum(1 for i in INVS if i in src)}/6")
    ok("audit_log", "VbrAuditRecord" in src and "export_audit_log_jsonl" in src, "JSONL export")
    ok("schema_version", "vbr-v1.0" in src, "vbr-v1.0")
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
    logger = configure_test_logging("check_verifier_benchmark_releases")
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
