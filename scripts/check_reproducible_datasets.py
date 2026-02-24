#!/usr/bin/env python3
"""bd-2ad0: Reproducible migration and incident datasets — verification gate.

Usage:
    python3 scripts/check_reproducible_datasets.py [--json]
"""

import json
import os
import re
import subprocess
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools",
                     "migration_incident_datasets.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_16", "bd-2ad0_contract.md")

BEAD = "bd-2ad0"
SECTION = "16"

REQUIRED_TYPES = [
    "MigrationScenario", "SecurityIncident", "BenchmarkBaseline",
    "CompatibilityMatrix", "TrustEvidence",
]
REQUIRED_EVENT_CODES = [
    "RDS-001", "RDS-002", "RDS-003", "RDS-004", "RDS-005",
    "RDS-006", "RDS-007", "RDS-008", "RDS-009", "RDS-010",
    "RDS-ERR-001", "RDS-ERR-002",
]
REQUIRED_INVARIANTS = [
    "INV-RDS-INTEGRITY", "INV-RDS-DETERMINISTIC", "INV-RDS-PROVENANCE",
    "INV-RDS-REPRODUCIBLE", "INV-RDS-VERSIONED", "INV-RDS-GATED",
]


def _read(path):
    with open(path) as f:
        return f.read()


def _checks():
    results = []

    def ok(name, passed, detail=""):
        results.append({"check": name, "passed": passed, "detail": detail})

    src = _read(IMPL)

    # 1. Source exists
    ok("source_exists", os.path.isfile(IMPL), IMPL)

    # 2. Module wiring
    mod_src = _read(MOD_RS)
    ok("module_wiring",
       "pub mod migration_incident_datasets;" in mod_src,
       "tools/mod.rs")

    # 3. Dataset types (5)
    found_types = [t for t in REQUIRED_TYPES if t in src]
    ok("dataset_types",
       len(found_types) >= 5,
       f"{len(found_types)}/5 types")

    # 4. Structs
    for st in ["DatasetEntry", "DatasetProvenance", "ReplayInstructions",
               "DatasetBundle", "DatasetCatalog", "ReproducibleDatasets"]:
        ok(f"struct_{st}", f"pub struct {st}" in src or f"struct {st}" in src, st)

    # 5. Content hash integrity
    ok("content_hash_integrity",
       "content_hash" in src and "Sha256" in src,
       "SHA-256 content hashing")

    # 6. Provenance metadata
    ok("provenance_metadata",
       "DatasetProvenance" in src and "source_bead" in src,
       "Provenance linked to source bead")

    # 7. Replay instructions
    ok("replay_instructions",
       "ReplayInstructions" in src and "commands" in src and "deterministic" in src,
       "Replay with commands and deterministic flag")

    # 8. Schema versioning
    ok("schema_versioning",
       "SCHEMA_VERSION" in src and "rds-v1.0" in src,
       "rds-v1.0")

    # 9. Bundle publication
    ok("bundle_publication",
       "publish_bundle" in src and "DatasetBundle" in src,
       "Bundle aggregation with hash")

    # 10. Catalog generation
    ok("catalog_generation",
       "generate_catalog" in src and "DatasetCatalog" in src,
       "Catalog with by_type counts")

    # 11. Event codes (12)
    found_codes = [c for c in REQUIRED_EVENT_CODES if c in src]
    ok("event_codes",
       len(found_codes) >= 12,
       f"{len(found_codes)}/12 codes")

    # 12. Invariants (6)
    found_invs = [i for i in REQUIRED_INVARIANTS if i in src]
    ok("invariants",
       len(found_invs) >= 6,
       f"{len(found_invs)}/6 invariants")

    # 13. Audit log
    ok("audit_log",
       "RdsAuditRecord" in src and "export_audit_log_jsonl" in src,
       "JSONL audit export")

    # 14. Spec alignment
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)

    # 15. Test coverage (count #[test])
    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage",
       test_count >= 22,
       f"{test_count} tests (>=22)")

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
    logger = configure_test_logging("check_reproducible_datasets")
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
            "gate_script": os.path.basename(__file__),
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
