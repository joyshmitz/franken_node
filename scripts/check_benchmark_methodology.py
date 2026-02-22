#!/usr/bin/env python3
"""bd-nbh7: Benchmark/verifier methodology publications — verification gate."""

import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools",
                     "benchmark_methodology.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_16", "bd-nbh7_contract.md")

BEAD = "bd-nbh7"
SECTION = "16"

REQUIRED_TOPICS = ["BenchmarkDesign", "VerifierArchitecture", "MetricDefinition",
                    "ReproducibilityProtocol", "ThreatModeling"]
REQUIRED_STATUSES = ["Draft", "Review", "Published", "Archived"]
REQUIRED_SECTIONS = ["abstract", "introduction", "methodology", "results",
                      "reproducibility", "limitations"]
REQUIRED_CODES = [f"BMP-{str(i).zfill(3)}" for i in range(1, 11)] + ["BMP-ERR-001", "BMP-ERR-002"]
REQUIRED_INVARIANTS = [
    "INV-BMP-STRUCTURED", "INV-BMP-DETERMINISTIC", "INV-BMP-CITABLE",
    "INV-BMP-REPRODUCIBLE", "INV-BMP-VERSIONED", "INV-BMP-AUDITABLE",
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
    ok("module_wiring", "pub mod benchmark_methodology;" in _read(MOD_RS), "tools/mod.rs")

    found_topics = [t for t in REQUIRED_TOPICS if t in src]
    ok("methodology_topics", len(found_topics) >= 5, f"{len(found_topics)}/5")

    found_statuses = [s for s in REQUIRED_STATUSES if s in src]
    ok("pub_statuses", len(found_statuses) >= 4, f"{len(found_statuses)}/4")

    ok("status_transitions", "valid_transitions" in src, "State machine enforcement")

    found_secs = [s for s in REQUIRED_SECTIONS if f'"{s}"' in src]
    ok("required_sections", len(found_secs) >= 6, f"{len(found_secs)}/6")

    for st in ["Publication", "Citation", "ChecklistItem",
               "PublicationCatalog", "BenchmarkMethodology"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)

    ok("content_hashing", "content_hash" in src and "Sha256" in src, "SHA-256 integrity")
    ok("reproducibility_checklist", "ChecklistItem" in src and "reproducibility_checklist" in src,
       "Checklist with verified flag")
    ok("catalog_generation", "generate_catalog" in src and "PublicationCatalog" in src,
       "Catalog with by_topic/by_status")
    ok("search_by_topic", "search_by_topic" in src, "Topic-based search")

    found_codes = [c for c in REQUIRED_CODES if c in src]
    ok("event_codes", len(found_codes) >= 12, f"{len(found_codes)}/12")

    found_invs = [i for i in REQUIRED_INVARIANTS if i in src]
    ok("invariants", len(found_invs) >= 6, f"{len(found_invs)}/6")

    ok("audit_log", "BmpAuditRecord" in src and "export_audit_log_jsonl" in src, "JSONL export")
    ok("pub_version", "PUB_VERSION" in src and "bmp-v1.0" in src, "bmp-v1.0")
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)

    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 22, f"{test_count} tests (>=22)")

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
