#!/usr/bin/env python3
"""bd-yz3t gate: Verifier Toolkit for Independent Validation (Section 14).

Validates the Rust implementation in
crates/franken-node/src/tools/verifier_toolkit.rs against
the spec contract docs/specs/section_14/bd-yz3t_contract.md.
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


SRC = ROOT / "crates" / "franken-node" / "src" / "tools" / "verifier_toolkit.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "tools" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_14" / "bd-yz3t_contract.md"

CLAIM_TYPES = [
    "benchmark_performance",
    "security_posture",
    "trust_property",
    "compatibility_guarantee",
    "migration_readiness",
]

EVENT_CODES = [
    "VTK-001", "VTK-002", "VTK-003", "VTK-004", "VTK-005",
    "VTK-006", "VTK-007", "VTK-008", "VTK-009", "VTK-010",
    "VTK-ERR-001", "VTK-ERR-002",
]

INVARIANTS = [
    "INV-VTK-SCHEMA",
    "INV-VTK-DETERMINISTIC",
    "INV-VTK-EVIDENCE-CHAIN",
    "INV-VTK-INDEPENDENT",
    "INV-VTK-VERSIONED",
    "INV-VTK-GATED",
]

VALIDATION_STEPS = [
    "Schema validation",
    "Evidence hash verification",
    "Metrics threshold",
    "Cross-validation",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def check_source_exists() -> tuple[str, bool, str]:
    ok = SRC.is_file()
    return ("source_exists", ok, f"Source file exists: {SRC.name}")


def check_module_wiring() -> tuple[str, bool, str]:
    content = _read(MOD_RS)
    ok = "pub mod verifier_toolkit;" in content
    return ("module_wiring", ok, "Module wired in tools/mod.rs")


def check_structs() -> tuple[str, bool, str]:
    src = _read(SRC)
    required = [
        "struct VerifiableClaim",
        "struct ClaimValidationResult",
        "struct ValidationStep",
        "struct ConfidenceInterval",
        "struct ValidationReport",
        "struct EvidenceLink",
        "struct VtkAuditRecord",
        "struct ToolkitConfig",
        "struct VerifierToolkit",
    ]
    missing = [s for s in required if s not in src]
    ok = len(missing) == 0
    detail = f"All {len(required)} structs present" if ok else f"Missing: {missing}"
    return ("structs", ok, detail)


def check_claim_types() -> tuple[str, bool, str]:
    src = _read(SRC)
    missing = [c for c in CLAIM_TYPES if c not in src]
    ok = len(missing) == 0 and "enum ClaimType" in src
    return ("claim_types", ok, f"5 claim types: {5 - len(missing)}/5")


def check_validation_pipeline() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "validate_schema" in src,
        "verify_evidence_hash" in src,
        "check_metrics_thresholds" in src,
        "cross_check_claim" in src,
        "validate_single_claim" in src,
        "validate_claims" in src,
    ]
    ok = all(checks)
    return ("validation_pipeline", ok, f"Validation pipeline: {sum(checks)}/6 functions")


def check_evidence_chain() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "struct EvidenceLink" in src,
        "parent_hash" in src,
        "current_hash" in src,
        "evidence_chain" in src,
        "step_hash" in src,
    ]
    ok = all(checks)
    return ("evidence_chain", ok, f"Evidence chain: {sum(checks)}/5 checks")


def check_verdict_types() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "enum ValidationVerdict" in src,
        "Pass" in src,
        "Fail" in src,
        "Partial" in src,
    ]
    ok = all(checks)
    return ("verdict_types", ok, f"Verdict types (Pass/Fail/Partial): {sum(checks)}/4")


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


def check_report_structure() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "toolkit_version" in src,
        "content_hash" in src,
        "overall_verdict" in src,
        "claims_validated" in src,
        "claims_passed" in src,
        "claims_failed" in src,
    ]
    ok = all(checks)
    return ("report_structure", ok, f"Report structure: {sum(checks)}/6 fields")


def check_spec_alignment() -> tuple[str, bool, str]:
    if not SPEC.is_file():
        return ("spec_alignment", False, "Spec contract not found")
    spec = _read(SPEC)
    checks = [
        "bd-yz3t" in spec,
        "Verifier Toolkit" in spec,
        "Section" in spec and "14" in spec,
    ]
    ok = all(checks)
    return ("spec_alignment", ok, "Spec contract aligns with implementation")


def check_audit_logging() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "struct VtkAuditRecord" in src,
        "audit_log" in src,
        "export_audit_log_jsonl" in src,
    ]
    ok = all(checks)
    return ("audit_logging", ok, f"Audit logging: {sum(checks)}/3 checks")


def check_test_coverage() -> tuple[str, bool, str]:
    src = _read(SRC)
    test_count = len(re.findall(r"#\[test\]", src))
    ok = test_count >= 28
    return ("test_coverage", ok, f"Rust unit tests: {test_count} (target >= 28)")


ALL_CHECKS = [
    check_source_exists,
    check_module_wiring,
    check_structs,
    check_claim_types,
    check_validation_pipeline,
    check_evidence_chain,
    check_verdict_types,
    check_event_codes,
    check_invariants,
    check_report_structure,
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
    if not results:
        print("SELF-TEST FAIL: no checks returned", file=sys.stderr)
        return False
    for entry in results:
        if not isinstance(entry, dict) or "check" not in entry or "passed" not in entry:
            print(f"SELF-TEST FAIL: malformed entry: {entry}", file=sys.stderr)
            return False
    print(f"SELF-TEST OK: {len(results)} checks returned", file=sys.stderr)
    return True


def main() -> None:
    logger = configure_test_logging("check_verifier_toolkit")
    parser = argparse.ArgumentParser(description="bd-yz3t gate: Verifier Toolkit")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(0 if self_test() else 1)

    results = run_all()
    total = len(results)
    n_passed = sum(1 for r in results if r["passed"])
    n_failed = total - n_passed
    verdict = "PASS" if n_failed == 0 else "FAIL"

    if args.json:
        output = {
            "bead_id": "bd-yz3t",
            "title": "Verifier toolkit for independent validation",
            "section": "14",
            "verdict": verdict,
            "overall_pass": n_failed == 0,
            "total": total,
            "passed": n_passed,
            "failed": n_failed,
            "checks": results,
        }
        print(json.dumps(output, indent=2))
    else:
        for r in results:
            status = "PASS" if r["passed"] else "FAIL"
            print(f"  [{status}] {r['check']}: {r['detail']}")
        print(f"\n  {n_passed}/{total} checks passed — {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
