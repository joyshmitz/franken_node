#!/usr/bin/env python3
"""bd-2kd9 verification gate for claim compiler and public trust scoreboard pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BEAD = "bd-2kd9"
SECTION = "10.17"

SPEC_FILE = ROOT / "docs/specs/section_10_17/bd-2kd9_contract.md"
IMPL_FILE = ROOT / "crates/franken-node/src/connector/claim_compiler.rs"
CONNECTOR_MOD_FILE = ROOT / "crates/franken-node/src/connector/mod.rs"
UNIT_TEST_FILE = ROOT / "tests/test_check_claim_compiler.py"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-2kd9/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-2kd9/verification_summary.md"

REQUIRED_EVENT_CODES = [
    "CLMC_001",
    "CLMC_002",
    "CLMC_003",
    "CLMC_004",
    "CLMC_005",
    "CLMC_006",
    "CLMC_007",
    "CLMC_008",
    "CLMC_009",
    "CLMC_010",
]

REQUIRED_ERROR_CODES = [
    "ERR_CLMC_EMPTY_CLAIM_TEXT",
    "ERR_CLMC_MISSING_SOURCE",
    "ERR_CLMC_NO_EVIDENCE_LINKS",
    "ERR_CLMC_INVALID_EVIDENCE_LINK",
    "ERR_CLMC_DUPLICATE_CLAIM_ID",
    "ERR_CLMC_SCOREBOARD_FULL",
    "ERR_CLMC_DIGEST_MISMATCH",
    "ERR_CLMC_SCHEMA_UNKNOWN",
]

REQUIRED_INVARIANTS = [
    "INV-CLMC-FAIL-CLOSED",
    "INV-CLMC-EVIDENCE-LINKED",
    "INV-CLMC-SCOREBOARD-ATOMIC",
    "INV-CLMC-DETERMINISTIC",
    "INV-CLMC-SIGNED-EVIDENCE",
    "INV-CLMC-SCHEMA-VERSIONED",
    "INV-CLMC-AUDIT-COMPLETE",
]

REQUIRED_IMPL_TOKENS = [
    "struct ClaimCompiler",
    "struct TrustScoreboard",
    "struct CompiledClaim",
    "struct ScoreEntry",
    "struct ClaimSource",
    "struct EvidenceLink",
    "struct RawClaim",
    "struct ScoreboardSnapshot",
    "fn compile_claim",
    "fn publish_batch",
    "fn snapshot",
    "fn verify_snapshot_digest",
    "BTreeMap",
    "SCHEMA_VERSION",
    "compute_compilation_digest",
    "compute_scoreboard_digest",
    "validate_evidence_uri",
    "struct ClaimCompilerEvent",
    "enum ClaimCompilerError",
]


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "passed": ok, "detail": detail or ("ok" if ok else "FAIL")}


def _checks() -> list[dict]:
    checks: list[dict] = []
    impl_src = _read(IMPL_FILE)
    spec_src = _read(SPEC_FILE)
    connector_mod_src = _read(CONNECTOR_MOD_FILE)

    # File existence
    checks.append(_check("Spec file exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("Implementation file exists", IMPL_FILE.exists(), str(IMPL_FILE)))
    checks.append(_check(
        "Connector module wired",
        "pub mod claim_compiler;" in connector_mod_src,
        "pub mod claim_compiler; in connector/mod.rs",
    ))

    # Implementation tokens
    for token in REQUIRED_IMPL_TOKENS:
        checks.append(_check(f"Impl token '{token}'", token in impl_src, token))

    # Event codes (in both impl and spec)
    for code in REQUIRED_EVENT_CODES:
        checks.append(_check(
            f"Event code {code}",
            code in impl_src and code in spec_src,
            code,
        ))

    # Error codes (in both impl and spec)
    for code in REQUIRED_ERROR_CODES:
        checks.append(_check(
            f"Error code {code}",
            code in impl_src and code in spec_src,
            code,
        ))

    # Invariants (in both impl and spec)
    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(
            f"Invariant {inv}",
            inv in impl_src and inv in spec_src,
            inv,
        ))

    # Rust unit test count
    test_count = impl_src.count("#[test]")
    checks.append(_check("Rust unit tests >= 20", test_count >= 20, f"found {test_count}"))

    # BTreeMap usage for deterministic ordering
    checks.append(_check(
        "BTreeMap used for scoreboard entries",
        "BTreeMap<String, ScoreEntry>" in impl_src,
        "BTreeMap<String, ScoreEntry>",
    ))

    # SHA-256 digest
    checks.append(_check(
        "SHA-256 digest computation",
        "Sha256" in impl_src and "hex::encode" in impl_src,
        "Sha256 + hex::encode",
    ))

    # Python test file exists
    checks.append(_check("Python checker unit test exists", UNIT_TEST_FILE.exists(), str(UNIT_TEST_FILE)))

    # Evidence and summary files
    checks.append(_check("Evidence file exists", EVIDENCE_FILE.exists(), str(EVIDENCE_FILE)))
    checks.append(_check("Summary file exists", SUMMARY_FILE.exists(), str(SUMMARY_FILE)))

    return checks


def run_all() -> dict:
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "schema_version": "claim-compiler-v1.0",
        "bead_id": BEAD,
        "section": SECTION,
        "title": "Claim compiler and public trust scoreboard pipeline",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "event_codes": REQUIRED_EVENT_CODES,
        "error_codes": REQUIRED_ERROR_CODES,
        "invariants": REQUIRED_INVARIANTS,
        "pipeline_contract": {
            "fail_closed_on_unverifiable_claims": True,
            "scoreboard_updates_publish_signed_evidence_links": True,
            "deterministic_btreemap_ordering": True,
            "schema_versioned_outputs": True,
            "atomic_scoreboard_updates": True,
        },
    }


def write_report(result: dict, report_path: Path | None = None) -> None:
    path = report_path or (ROOT / "artifacts/10.17/claim_compiler_report.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def self_test() -> dict:
    checks: list[dict] = []
    checks.append(_check("event code count >= 10", len(REQUIRED_EVENT_CODES) >= 10))
    checks.append(_check("error code count >= 8", len(REQUIRED_ERROR_CODES) >= 8))
    checks.append(_check("invariant count >= 7", len(REQUIRED_INVARIANTS) >= 7))
    checks.append(_check("impl token count >= 15", len(REQUIRED_IMPL_TOKENS) >= 15))

    result = run_all()
    checks.append(_check("run_all has verdict", result.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_all has checks", isinstance(result.get("checks"), list)))
    checks.append(_check("run_all checks non-empty", len(result.get("checks", [])) > 20))

    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "name": "check_claim_compiler",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": verdict,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="bd-2kd9 checker")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--build-report", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        st = self_test()
        if args.json:
            print(json.dumps(st, indent=2))
        else:
            print(f"self-test: {st['verdict']} ({st['passed']}/{st['passed'] + st['failed']})")
        sys.exit(0 if st["verdict"] == "PASS" else 1)

    result = run_all()
    if args.build_report:
        write_report(result)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"bd-2kd9: {result['verdict']} ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "+" if c["passed"] else "x"
            print(f"[{mark}] {c['check']}: {c['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
