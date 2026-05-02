#!/usr/bin/env python3
"""bd-2fkq: Migration speed and failure-rate metrics — verification gate."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL = ROOT / "crates/franken-node/src/tools/migration_speed_failure_metrics.rs"
MOD_RS = ROOT / "crates/franken-node/src/tools/mod.rs"
SPEC = ROOT / "docs/specs/section_14/bd-2fkq_contract.md"
BEAD, SECTION = "bd-2fkq", "14"

CODES = [f"MSF-{str(i).zfill(3)}" for i in range(1, 11)] + ["MSF-ERR-001", "MSF-ERR-002"]
INVS = ["INV-MSF-PHASED", "INV-MSF-CATEGORIZED", "INV-MSF-DETERMINISTIC", "INV-MSF-GATED", "INV-MSF-VERSIONED", "INV-MSF-AUDITABLE"]


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
    ok("module_wiring", "pub mod migration_speed_failure_metrics;" in _read(MOD_RS))
    ok("migration_phases", all(t in src for t in ["Assessment", "DependencyResolution", "CodeAdaptation", "TestValidation", "Deployment"]), "5 phases")
    ok("failure_types", all(t in src for t in ["DependencyConflict", "ApiIncompatibility", "RuntimeError", "TestRegression", "ConfigurationError"]), "5 types")
    for st in ["MigrationRecord", "PhaseStats", "FailureStats", "MigrationSpeedReport", "MigrationSpeedFailureMetrics"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)
    ok("phase_durations", "PhaseDuration" in src and "duration_ms" in src, "Per-phase timing")
    ok("failure_rate", "failure_rate" in src and "MAX_FAILURE_RATE" in src, "Rate with threshold")
    ok("speed_computation", "avg_total_duration_ms" in src and "p90_duration_ms" in src, "Avg + p90")
    ok("threshold_gating", "exceeds_threshold" in src and "MAX_FAILURE_RATE" in src, "Threshold enforcement")
    ok("content_hash", "content_hash" in src and "Sha256" in src, "SHA-256 hashing")
    ok("event_codes", sum(1 for c in CODES if c in src) >= 12, f"{sum(1 for c in CODES if c in src)}/12")
    ok("invariants", sum(1 for i in INVS if i in src) >= 6, f"{sum(1 for i in INVS if i in src)}/6")
    ok("audit_log", "MsfAuditRecord" in src and "export_audit_log_jsonl" in src, "JSONL export")
    ok("metric_version", "msf-v1.0" in src, "msf-v1.0")
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
    configure_test_logging("check_migration_speed_failure_metrics")
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
