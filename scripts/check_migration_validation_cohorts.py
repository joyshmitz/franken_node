#!/usr/bin/env python3
"""bd-sxt5: Migration validation cohorts — verification gate."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL = ROOT / "crates/franken-node/src/tools/migration_validation_cohorts.rs"
MOD_RS = ROOT / "crates/franken-node/src/tools/mod.rs"
SPEC = ROOT / "docs/specs/section_15/bd-sxt5_contract.md"
BEAD, SECTION = "bd-sxt5", "15"

CODES = [f"MVC-{str(i).zfill(3)}" for i in range(1, 11)] + ["MVC-ERR-001", "MVC-ERR-002"]
INVS = ["INV-MVC-COHORTED", "INV-MVC-DETERMINISTIC", "INV-MVC-REPRODUCIBLE", "INV-MVC-GATED", "INV-MVC-VERSIONED", "INV-MVC-AUDITABLE"]


def _read(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def _checks() -> list[dict[str, object]]:
    results = []

    def ok(name: str, passed: bool, detail: str = "") -> None:
        results.append({"check": name, "passed": passed, "detail": detail})

    src = _read(IMPL)
    ok("source_exists", IMPL.is_file(), str(IMPL))
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
    ok("spec_alignment", SPEC.is_file(), str(SPEC))
    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 22, f"{test_count} tests")
    return results


def self_test() -> bool:
    results = _checks()
    if len(results) < 16:
        msg = f"expected at least 16 checks, found {len(results)}"
        raise RuntimeError(msg)
    for result in results:
        if "check" not in result or "passed" not in result:
            msg = f"malformed check result: {result!r}"
            raise RuntimeError(msg)
    print(f"self_test: {len(results)} checks OK", file=sys.stderr)
    return True


def main() -> None:
    configure_test_logging("check_migration_validation_cohorts")
    as_json = "--json" in sys.argv
    if "--self-test" in sys.argv:
        self_test()
        return
    results = _checks()
    passed = sum(1 for result in results if result["passed"])
    total = len(results)
    verdict = "PASS" if passed == total else "FAIL"
    if as_json:
        print(
            json.dumps(
                {
                    "bead_id": BEAD,
                    "section": SECTION,
                    "gate_script": Path(__file__).name,
                    "checks_passed": passed,
                    "checks_total": total,
                    "verdict": verdict,
                    "checks": results,
                },
                indent=2,
            )
        )
    else:
        for result in results:
            state = "PASS" if result["passed"] else "FAIL"
            print(f"  [{state}] {result['check']}: {result['detail']}")
        print(f"\n{BEAD}: {passed}/{total} checks — {verdict}")
    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
