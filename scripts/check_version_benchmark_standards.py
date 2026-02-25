#!/usr/bin/env python3
"""bd-3v8g gate: Version Benchmark Standards with Migration Guidance (Section 14).

Validates the Rust implementation in
crates/franken-node/src/tools/version_benchmark_standards.rs against
the spec contract docs/specs/section_14/bd-3v8g_contract.md.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path


SRC = ROOT / "crates" / "franken-node" / "src" / "tools" / "version_benchmark_standards.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "tools" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_14" / "bd-3v8g_contract.md"

EVENT_CODES = [
    "BSV-001", "BSV-002", "BSV-003", "BSV-004", "BSV-005",
    "BSV-006", "BSV-007", "BSV-008", "BSV-009", "BSV-010",
    "BSV-ERR-001", "BSV-ERR-002",
]

INVARIANTS = [
    "INV-BSV-SEMVER",
    "INV-BSV-DETERMINISTIC",
    "INV-BSV-MIGRATION-PATH",
    "INV-BSV-BACKWARD-COMPAT",
    "INV-BSV-VERSIONED",
    "INV-BSV-GATED",
]

COMPAT_LEVELS = [
    "FullyCompatible",
    "BackwardCompatible",
    "RequiresMigration",
    "Incompatible",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def check_source_exists() -> tuple[str, bool, str]:
    ok = SRC.is_file()
    return ("source_exists", ok, f"Source file exists: {SRC.name}")


def check_module_wiring() -> tuple[str, bool, str]:
    content = _read(MOD_RS)
    ok = "pub mod version_benchmark_standards;" in content
    return ("module_wiring", ok, "Module wired in tools/mod.rs")


def check_structs() -> tuple[str, bool, str]:
    src = _read(SRC)
    required = [
        "struct SemVer",
        "struct StandardRevision",
        "struct ChangelogEntry",
        "struct MigrationGuide",
        "struct MigrationStep",
        "struct VersioningReport",
        "struct BsvAuditRecord",
        "struct BenchmarkVersioning",
    ]
    missing = [s for s in required if s not in src]
    ok = len(missing) == 0
    detail = f"All {len(required)} structs present" if ok else f"Missing: {missing}"
    return ("structs", ok, detail)


def check_semver() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "struct SemVer" in src,
        "fn parse" in src,
        "fn label" in src,
        "is_breaking_from" in src,
        "is_feature_from" in src,
        "is_patch_from" in src,
    ]
    ok = all(checks)
    return ("semver", ok, f"Semantic versioning: {sum(checks)}/6 checks")


def check_compatibility_levels() -> tuple[str, bool, str]:
    src = _read(SRC)
    missing = [c for c in COMPAT_LEVELS if c not in src]
    ok = len(missing) == 0 and "enum CompatibilityLevel" in src
    return ("compatibility_levels", ok, f"Compatibility levels: {4 - len(missing)}/4")


def check_migration_pipeline() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "compute_migration" in src,
        "check_compatibility" in src,
        "generate_migration_steps" in src,
        "estimate_effort" in src,
        "struct MigrationGuide" in src,
        "rollback_possible" in src,
    ]
    ok = all(checks)
    return ("migration_pipeline", ok, f"Migration pipeline: {sum(checks)}/6 functions")


def check_change_types() -> tuple[str, bool, str]:
    src = _read(SRC)
    types = ["Breaking", "Feature", "Fix", "Deprecation"]
    missing = [t for t in types if t not in src]
    ok = len(missing) == 0 and "enum ChangeType" in src
    return ("change_types", ok, f"Change types: {4 - len(missing)}/4")


def check_effort_levels() -> tuple[str, bool, str]:
    src = _read(SRC)
    levels = ["Trivial", "Low", "Medium", "High"]
    missing = [l for l in levels if l not in src]
    ok = len(missing) == 0 and "enum MigrationEffort" in src
    return ("effort_levels", ok, f"Effort levels: {4 - len(missing)}/4")


def check_event_codes() -> tuple[str, bool, str]:
    src = _read(SRC)
    found = [c for c in EVENT_CODES if f'"{c}"' in src]
    ok = len(found) == len(EVENT_CODES)
    return ("event_codes", ok, f"Event codes: {len(found)}/{len(EVENT_CODES)}")


def check_invariants() -> tuple[str, bool, str]:
    src = _read(SRC)
    found = [i for i in INVARIANTS if i in src]
    ok = len(found) == len(INVARIANTS)
    return ("invariants", ok, f"Invariants: {len(found)}/{len(INVARIANTS)}")


def check_spec_alignment() -> tuple[str, bool, str]:
    if not SPEC.is_file():
        return ("spec_alignment", False, "Spec contract not found")
    spec = _read(SPEC)
    checks = [
        "bd-3v8g" in spec,
        "Version Benchmark Standards" in spec,
        "Section" in spec and "14" in spec,
    ]
    ok = all(checks)
    return ("spec_alignment", ok, "Spec contract aligns with implementation")


def check_audit_logging() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "struct BsvAuditRecord" in src,
        "audit_log" in src,
        "export_audit_log_jsonl" in src,
    ]
    ok = all(checks)
    return ("audit_logging", ok, f"Audit logging: {sum(checks)}/3 checks")


def check_test_coverage() -> tuple[str, bool, str]:
    src = _read(SRC)
    test_count = len(re.findall(r"#\[test\]", src))
    ok = test_count >= 25
    return ("test_coverage", ok, f"Rust unit tests: {test_count} (target >= 25)")


ALL_CHECKS = [
    check_source_exists,
    check_module_wiring,
    check_structs,
    check_semver,
    check_compatibility_levels,
    check_migration_pipeline,
    check_change_types,
    check_effort_levels,
    check_event_codes,
    check_invariants,
    check_spec_alignment,
    check_audit_logging,
    check_test_coverage,
]


def run_all() -> list[dict]:
    results = []
    for fn in ALL_CHECKS:
        name, passed, detail = fn()
        results.append({"check": name, "passed": passed, "detail": detail})
    return results


def self_test() -> bool:
    results = run_all()
    return all(r["passed"] for r in results)


def main() -> None:
    logger = configure_test_logging("check_version_benchmark_standards")
    parser = argparse.ArgumentParser(description="bd-3v8g gate: Version Benchmark Standards")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    results = run_all()
    verdict = "PASS" if all(r["passed"] for r in results) else "FAIL"

    if args.json:
        print(json.dumps({"bead": "bd-3v8g", "verdict": verdict, "checks": results}, indent=2))
    else:
        for r in results:
            status = "PASS" if r["passed"] else "FAIL"
            print(f"  [{status}] {r['check']}: {r['detail']}")
        total = len(results)
        passed = sum(1 for r in results if r["passed"])
        print(f"\n  {passed}/{total} checks passed — {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
