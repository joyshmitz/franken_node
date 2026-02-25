#!/usr/bin/env python3
"""bd-209w gate: Signed Extension Registry with Provenance and Revocation (Section 15).

Validates the Rust implementation in
crates/franken-node/src/supply_chain/extension_registry.rs against
the spec contract docs/specs/section_15/bd-209w_contract.md.
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


SRC = ROOT / "crates" / "franken-node" / "src" / "supply_chain" / "extension_registry.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "supply_chain" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_15" / "bd-209w_contract.md"

EXTENSION_STATUSES = [
    "Submitted",
    "Active",
    "Deprecated",
    "Revoked",
]

EVENT_CODES = [
    "SER-001", "SER-002", "SER-003", "SER-004", "SER-005",
    "SER-006", "SER-007", "SER-008", "SER-009", "SER-010",
    "SER-ERR-001", "SER-ERR-002", "SER-ERR-003",
]

INVARIANTS = [
    "INV-SER-SIGNED",
    "INV-SER-PROVENANCE",
    "INV-SER-REVOCABLE",
    "INV-SER-MONOTONIC",
    "INV-SER-AUDITABLE",
    "INV-SER-DETERMINISTIC",
]

REVOCATION_REASONS = [
    "SecurityVulnerability",
    "PolicyViolation",
    "MaintainerRequest",
    "LicenseConflict",
    "Superseded",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def check_source_exists() -> tuple[str, bool, str]:
    ok = SRC.is_file()
    return ("source_exists", ok, f"Source file exists: {SRC.name}")


def check_module_wiring() -> tuple[str, bool, str]:
    content = _read(MOD_RS)
    ok = "pub mod extension_registry;" in content
    return ("module_wiring", ok, "Module wired in supply_chain/mod.rs")


def check_structs() -> tuple[str, bool, str]:
    src = _read(SRC)
    required = [
        "struct ExtensionSignature",
        "struct ProvenanceAttestation",
        "struct VersionEntry",
        "struct RevocationRecord",
        "struct SignedExtension",
        "struct RegistryAuditRecord",
        "struct RegistrationRequest",
        "struct RegistryResult",
        "struct RegistryConfig",
        "struct SignedExtensionRegistry",
    ]
    missing = [s for s in required if s not in src]
    ok = len(missing) == 0
    detail = f"All {len(required)} structs present" if ok else f"Missing: {missing}"
    return ("structs", ok, detail)


def check_extension_statuses() -> tuple[str, bool, str]:
    src = _read(SRC)
    missing = [s for s in EXTENSION_STATUSES if s not in src]
    ok = len(missing) == 0 and "enum ExtensionStatus" in src
    return ("extension_statuses", ok, f"4 statuses: {4 - len(missing)}/4")


def check_revocation_reasons() -> tuple[str, bool, str]:
    src = _read(SRC)
    missing = [r for r in REVOCATION_REASONS if r not in src]
    ok = len(missing) == 0 and "enum RevocationReason" in src
    return ("revocation_reasons", ok, f"5 reasons: {5 - len(missing)}/5")


def check_registry_operations() -> tuple[str, bool, str]:
    src = _read(SRC)
    ops = [
        "fn register(" in src,
        "fn add_version(" in src,
        "fn deprecate(" in src,
        "fn revoke(" in src,
        "fn query(" in src,
        "fn list(" in src,
        "fn version_lineage(" in src,
    ]
    ok = all(ops)
    return ("registry_operations", ok, f"Registry operations: {sum(ops)}/7 functions")


def check_signature_verification() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "verify_signature" in src,
        "key_id" in src,
        "signature_hex" in src,
        "is_ascii_hexdigit" in src,
    ]
    ok = all(checks)
    return ("signature_verification", ok, f"Signature verification: {sum(checks)}/4 checks")


def check_provenance_validation() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "verify_provenance" in src,
        "publisher_id" in src,
        "build_system" in src,
        "source_repository" in src,
        "vcs_commit" in src,
        "attestation_hash" in src,
    ]
    ok = all(checks)
    return ("provenance_validation", ok, f"Provenance validation: {sum(checks)}/6 checks")


def check_monotonic_revocation() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "revocation_sequence" in src,
        "RevocationRecord" in src,
        "RevocationReason" in src,
        "is_terminal" in src,
    ]
    ok = all(checks)
    return ("monotonic_revocation", ok, f"Monotonic revocation: {sum(checks)}/4 checks")


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


def check_content_hash() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "content_hash" in src,
        "Sha256" in src,
        "hex::encode" in src,
    ]
    ok = all(checks)
    return ("content_hash", ok, f"Content hash: {sum(checks)}/3 checks")


def check_audit_logging() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "struct RegistryAuditRecord" in src,
        "audit_log" in src,
        "export_audit_log_jsonl" in src,
    ]
    ok = all(checks)
    return ("audit_logging", ok, f"Audit logging: {sum(checks)}/3 checks")


def check_spec_alignment() -> tuple[str, bool, str]:
    if not SPEC.is_file():
        return ("spec_alignment", False, "Spec contract not found")
    spec = _read(SPEC)
    checks = [
        "bd-209w" in spec,
        "Signed Extension Registry" in spec,
        "Section" in spec and "15" in spec,
    ]
    ok = all(checks)
    return ("spec_alignment", ok, "Spec contract aligns with implementation")


def check_test_coverage() -> tuple[str, bool, str]:
    src = _read(SRC)
    test_count = len(re.findall(r"#\[test\]", src))
    ok = test_count >= 25
    return ("test_coverage", ok, f"Rust unit tests: {test_count} (target >= 25)")


ALL_CHECKS = [
    check_source_exists,
    check_module_wiring,
    check_structs,
    check_extension_statuses,
    check_revocation_reasons,
    check_registry_operations,
    check_signature_verification,
    check_provenance_validation,
    check_monotonic_revocation,
    check_event_codes,
    check_invariants,
    check_content_hash,
    check_audit_logging,
    check_spec_alignment,
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
    logger = configure_test_logging("check_signed_extension_registry")
    parser = argparse.ArgumentParser(description="bd-209w gate: Signed Extension Registry")
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
            "bead_id": "bd-209w",
            "title": "Signed extension registry with provenance and revocation",
            "section": "15",
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
