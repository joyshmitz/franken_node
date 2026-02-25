#!/usr/bin/env python3
"""
Section 10.7 verification gate (bd-1rwq).

Aggregates verification evidence from all Section 10.7 beads and validates
that the conformance and verification infrastructure is complete.

Usage:
    python3 scripts/check_section_10_7_gate.py [--json] [--self-test]
"""

import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone
from pathlib import Path


# Section 10.7 beads and their evidence paths
SECTION_BEADS = [
    {
        "bead_id": "bd-2ja",
        "title": "Compatibility golden corpus and fixture metadata schema",
        "evidence": ROOT / "artifacts" / "section_10_7" / "bd-2ja" / "verification_evidence.json",
        "gate_script": ROOT / "scripts" / "check_compatibility_corpus.py",
    },
    {
        "bead_id": "bd-s6y",
        "title": "Canonical trust protocol vectors from 10.13 + 10.14",
        "evidence": ROOT / "artifacts" / "section_10_7" / "bd-s6y" / "verification_evidence.json",
        "gate_script": ROOT / "scripts" / "check_canonical_vectors.py",
    },
    {
        "bead_id": "bd-1ul",
        "title": "Fuzz/adversarial tests for migration and shim logic",
        "evidence": ROOT / "artifacts" / "section_10_7" / "bd-1ul" / "verification_evidence.json",
        "gate_script": ROOT / "scripts" / "check_fuzz_testing.py",
    },
    {
        "bead_id": "bd-1u4",
        "title": "Metamorphic tests for compatibility invariants",
        "evidence": ROOT / "artifacts" / "section_10_7" / "bd-1u4" / "verification_evidence.json",
        "gate_script": ROOT / "scripts" / "check_metamorphic_testing.py",
    },
    {
        "bead_id": "bd-3ex",
        "title": "Verifier CLI conformance contract tests",
        "evidence": ROOT / "artifacts" / "section_10_7" / "bd-3ex" / "verification_evidence.json",
        "gate_script": ROOT / "scripts" / "check_verifier_contract.py",
    },
    {
        "bead_id": "bd-2pu",
        "title": "External-reproduction playbook and automation scripts",
        "evidence": ROOT / "artifacts" / "section_10_7" / "bd-2pu" / "verification_evidence.json",
        "gate_script": ROOT / "scripts" / "check_external_reproduction.py",
    },
]

# Golden corpus paths
CORPUS_MANIFEST = ROOT / "fixtures" / "conformance" / "corpus_manifest.json"
FIXTURE_SCHEMA = ROOT / "fixtures" / "conformance" / "fixture_metadata_schema.json"

# Fuzz paths
FUZZ_CORPUS_MIGRATION = ROOT / "fuzz" / "corpus" / "migration"
FUZZ_CORPUS_SHIM = ROOT / "fuzz" / "corpus" / "shim"

# External reproduction paths
PLAYBOOK = ROOT / "docs" / "reproduction_playbook.md"
CLAIMS_REGISTRY = ROOT / "docs" / "headline_claims.toml"

# Gate-level evidence paths
GATE_EVIDENCE = ROOT / "artifacts" / "section_10_7" / "bd-1rwq" / "verification_evidence.json"
GATE_SUMMARY = ROOT / "artifacts" / "section_10_7" / "bd-1rwq" / "verification_summary.md"
GATE_SPEC = ROOT / "docs" / "specs" / "section_10_7" / "bd-1rwq_contract.md"
GATE_TESTS = ROOT / "tests" / "test_check_section_10_7_gate.py"

REQUIRED_BANDS = {"core", "high_value", "edge", "unsafe"}


def _load_evidence(path):
    """Load and return evidence JSON, or None on failure."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _checks():
    """Run all gate checks and return list of results."""
    results = []

    # --- Check each bead evidence exists and has PASS verdict ---
    for bead in SECTION_BEADS:
        bead_id = bead["bead_id"]

        # Evidence file exists
        exists = bead["evidence"].exists()
        try:
            ev_rel = str(bead["evidence"].relative_to(ROOT))
        except ValueError:
            ev_rel = str(bead["evidence"])
        results.append({
            "check": f"evidence_exists:{bead_id}",
            "passed": exists,
            "detail": ev_rel if exists else f"missing: {ev_rel}",
        })

        # Evidence has PASS verdict
        evidence = _load_evidence(bead["evidence"])
        verdict = None
        if evidence:
            verdict = evidence.get("verdict", "UNKNOWN")
        passed = verdict == "PASS"
        results.append({
            "check": f"verdict_pass:{bead_id}",
            "passed": passed,
            "detail": f"verdict={verdict}" if verdict else "no evidence loaded",
        })

        # Gate script exists
        gs_exists = bead["gate_script"].exists()
        try:
            gs_rel = str(bead["gate_script"].relative_to(ROOT))
        except ValueError:
            gs_rel = str(bead["gate_script"])
        results.append({
            "check": f"gate_script_exists:{bead_id}",
            "passed": gs_exists,
            "detail": gs_rel if gs_exists else f"missing: {gs_rel}",
        })

    # --- Golden corpus coverage (bd-2ja) ---
    corpus_evidence = _load_evidence(SECTION_BEADS[0]["evidence"])
    if corpus_evidence:
        bands = set(corpus_evidence.get("bands_covered", []))
        covered = REQUIRED_BANDS.issubset(bands)
        results.append({
            "check": "corpus_band_coverage",
            "passed": covered,
            "detail": f"bands={sorted(bands)}, required={sorted(REQUIRED_BANDS)}",
        })
    else:
        results.append({
            "check": "corpus_band_coverage",
            "passed": False,
            "detail": "corpus evidence not loaded",
        })

    # Corpus manifest exists
    results.append({
        "check": "corpus_manifest_exists",
        "passed": CORPUS_MANIFEST.exists(),
        "detail": str(CORPUS_MANIFEST.relative_to(ROOT)),
    })

    # Fixture schema exists
    results.append({
        "check": "fixture_schema_exists",
        "passed": FIXTURE_SCHEMA.exists(),
        "detail": str(FIXTURE_SCHEMA.relative_to(ROOT)),
    })

    # --- Trust vector coverage (bd-s6y) ---
    vector_evidence = _load_evidence(SECTION_BEADS[1]["evidence"])
    if vector_evidence:
        summary = vector_evidence.get("summary", {})
        sources = summary.get("sources_passed", 0)
        results.append({
            "check": "vector_sources_verified",
            "passed": sources >= 4,
            "detail": f"sources_passed={sources}",
        })
        vectors = summary.get("vector_sets_passed", 0)
        results.append({
            "check": "vector_sets_verified",
            "passed": vectors >= 8,
            "detail": f"vector_sets_passed={vectors}",
        })
    else:
        results.append({
            "check": "vector_sources_verified",
            "passed": False,
            "detail": "vector evidence not loaded",
        })
        results.append({
            "check": "vector_sets_verified",
            "passed": False,
            "detail": "vector evidence not loaded",
        })

    # --- Fuzz coverage (bd-1ul) ---
    fuzz_evidence = _load_evidence(SECTION_BEADS[2]["evidence"])
    if fuzz_evidence:
        fuzz_total = fuzz_evidence.get("summary", {}).get("total_checks", 0)
        fuzz_passing = fuzz_evidence.get("summary", {}).get("passing_checks", 0)
        results.append({
            "check": "fuzz_checks_all_pass",
            "passed": fuzz_total > 0 and fuzz_passing == fuzz_total,
            "detail": f"passing={fuzz_passing}/{fuzz_total}",
        })
    else:
        results.append({
            "check": "fuzz_checks_all_pass",
            "passed": False,
            "detail": "fuzz evidence not loaded",
        })

    results.append({
        "check": "fuzz_corpus_migration_exists",
        "passed": FUZZ_CORPUS_MIGRATION.exists() and FUZZ_CORPUS_MIGRATION.is_dir(),
        "detail": str(FUZZ_CORPUS_MIGRATION.relative_to(ROOT)),
    })

    results.append({
        "check": "fuzz_corpus_shim_exists",
        "passed": FUZZ_CORPUS_SHIM.exists() and FUZZ_CORPUS_SHIM.is_dir(),
        "detail": str(FUZZ_CORPUS_SHIM.relative_to(ROOT)),
    })

    # --- Metamorphic coverage (bd-1u4) ---
    meta_evidence = _load_evidence(SECTION_BEADS[3]["evidence"])
    if meta_evidence:
        meta_total = meta_evidence.get("summary", {}).get("total", 0)
        meta_passing = meta_evidence.get("summary", {}).get("passing", 0)
        results.append({
            "check": "metamorphic_checks_all_pass",
            "passed": meta_total > 0 and meta_passing == meta_total,
            "detail": f"passing={meta_passing}/{meta_total}",
        })
    else:
        results.append({
            "check": "metamorphic_checks_all_pass",
            "passed": False,
            "detail": "metamorphic evidence not loaded",
        })

    # --- Verifier CLI (bd-3ex) ---
    cli_evidence = _load_evidence(SECTION_BEADS[4]["evidence"])
    if cli_evidence:
        contract_gate = cli_evidence.get("contract_gate", {})
        cli_passed = contract_gate.get("checks_passed", 0)
        cli_total = contract_gate.get("checks_total", 0)
        results.append({
            "check": "verifier_cli_checks_all_pass",
            "passed": cli_total > 0 and cli_passed == cli_total,
            "detail": f"passing={cli_passed}/{cli_total}",
        })
    else:
        results.append({
            "check": "verifier_cli_checks_all_pass",
            "passed": False,
            "detail": "CLI evidence not loaded",
        })

    # --- External reproduction (bd-2pu) ---
    repro_evidence = _load_evidence(SECTION_BEADS[5]["evidence"])
    if repro_evidence:
        repro_total = repro_evidence.get("total", 0)
        repro_passed_count = repro_evidence.get("passed", 0)
        results.append({
            "check": "reproduction_checks_all_pass",
            "passed": repro_total > 0 and repro_passed_count == repro_total,
            "detail": f"passing={repro_passed_count}/{repro_total}",
        })
    else:
        results.append({
            "check": "reproduction_checks_all_pass",
            "passed": False,
            "detail": "reproduction evidence not loaded",
        })

    results.append({
        "check": "playbook_exists",
        "passed": PLAYBOOK.exists(),
        "detail": str(PLAYBOOK.relative_to(ROOT)),
    })

    results.append({
        "check": "claims_registry_exists",
        "passed": CLAIMS_REGISTRY.exists(),
        "detail": str(CLAIMS_REGISTRY.relative_to(ROOT)),
    })

    # --- Gate-level artifacts ---
    results.append({
        "check": "gate_spec_exists",
        "passed": GATE_SPEC.exists(),
        "detail": str(GATE_SPEC.relative_to(ROOT)),
    })

    results.append({
        "check": "gate_tests_exist",
        "passed": GATE_TESTS.exists(),
        "detail": str(GATE_TESTS.relative_to(ROOT)),
    })

    results.append({
        "check": "gate_evidence_exists",
        "passed": GATE_EVIDENCE.exists(),
        "detail": str(GATE_EVIDENCE.relative_to(ROOT)),
    })

    results.append({
        "check": "gate_summary_exists",
        "passed": GATE_SUMMARY.exists(),
        "detail": str(GATE_SUMMARY.relative_to(ROOT)),
    })

    return results


def self_test():
    """Run all checks and return structured result."""
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    return {
        "name": "section_10_7_verification_gate",
        "bead": "bd-1rwq",
        "section": "10.7",
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "events": [
            "GATE_10_7_EVALUATION_STARTED",
            "GATE_10_7_BEAD_CHECKED",
            "GATE_10_7_CORPUS_COVERAGE",
            "GATE_10_7_VERDICT_EMITTED",
        ],
        "summary": {
            "total_beads": len(SECTION_BEADS),
            "beads_passing": sum(
                1 for b in SECTION_BEADS
                if (_load_evidence(b["evidence"]) or {}).get("verdict") == "PASS"
            ),
            "total_checks": len(checks),
            "passing_checks": passed,
            "failing_checks": failed,
        },
    }


def main():
    logger = configure_test_logging("check_section_10_7_gate")
    json_output = "--json" in sys.argv
    run_self_test = "--self-test" in sys.argv

    result = self_test()

    if json_output:
        print(json.dumps(result, indent=2))
    else:
        for c in result["checks"]:
            mark = "OK" if c["passed"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
        print(f"\nVerdict: {result['verdict']} ({result['passed']}/{result['passed'] + result['failed']})")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
