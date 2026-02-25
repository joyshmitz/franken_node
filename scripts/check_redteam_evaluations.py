#!/usr/bin/env python3
"""bd-3id1: Red-team and independent evaluations — verification gate."""

import json
import os
import re
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools",
                     "redteam_evaluations.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_16", "bd-3id1_contract.md")

BEAD = "bd-3id1"
SECTION = "16"

REQUIRED_SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
REQUIRED_TYPES = ["RedTeam", "PenetrationTest", "SecurityAudit", "IndependentReview", "FormalVerification"]
REQUIRED_STATUSES = ["Open", "InProgress", "Resolved", "Verified"]
REQUIRED_CODES = [f"RTE-{str(i).zfill(3)}" for i in range(1, 11)] + ["RTE-ERR-001", "RTE-ERR-002"]
REQUIRED_INVARIANTS = [
    "INV-RTE-SCOPED", "INV-RTE-DETERMINISTIC", "INV-RTE-CLASSIFIED",
    "INV-RTE-TRACKED", "INV-RTE-VERSIONED", "INV-RTE-AUDITABLE",
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
    ok("module_wiring", "pub mod redteam_evaluations;" in _read(MOD_RS), "tools/mod.rs")

    found_sev = [s for s in REQUIRED_SEVERITIES if s in src]
    ok("severity_levels", len(found_sev) >= 5, f"{len(found_sev)}/5")

    found_types = [t for t in REQUIRED_TYPES if t in src]
    ok("evaluation_types", len(found_types) >= 5, f"{len(found_types)}/5")

    found_sts = [s for s in REQUIRED_STATUSES if s in src]
    ok("remediation_statuses", len(found_sts) >= 4, f"{len(found_sts)}/4")

    ok("status_transitions", "valid_transitions" in src, "State machine enforcement")

    for st in ["Engagement", "Finding", "EvaluationCatalog", "RedTeamEvaluations"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)

    ok("scope_validation", "scope" in src and "rules_of_engagement" in src, "Scope and rules")
    ok("confidence_scoring", "confidence_score" in src, "Confidence score 0.0-1.0")
    ok("remediation_tracking", "update_remediation" in src, "Status transitions for findings")
    ok("catalog_generation", "generate_catalog" in src and "EvaluationCatalog" in src, "Catalog with by_type/by_severity")

    found_codes = [c for c in REQUIRED_CODES if c in src]
    ok("event_codes", len(found_codes) >= 12, f"{len(found_codes)}/12")

    found_invs = [i for i in REQUIRED_INVARIANTS if i in src]
    ok("invariants", len(found_invs) >= 6, f"{len(found_invs)}/6")

    ok("audit_log", "RteAuditRecord" in src and "export_audit_log_jsonl" in src, "JSONL export")
    ok("schema_version", "SCHEMA_VERSION" in src and "rte-v1.0" in src, "rte-v1.0")
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)

    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 22, f"{test_count} tests (>=22)")

    return results


def self_test():
    results = _checks()
    assert len(results) >= 15
    for r in results:
        assert "check" in r and "passed" in r
    print(f"self_test: {len(results)} checks OK", file=sys.stderr)
    return True


def main():
    logger = configure_test_logging("check_redteam_evaluations")
    as_json = "--json" in sys.argv
    if "--self-test" in sys.argv:
        self_test(); return

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
