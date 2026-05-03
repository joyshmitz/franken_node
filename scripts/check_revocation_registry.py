#!/usr/bin/env python3
"""Verification script for bd-y7lu: Revocation registry with monotonic heads."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL_PATH = ROOT / "crates/franken-node/src/supply_chain/revocation_registry.rs"
FIXTURE_PATH = ROOT / "fixtures/revocation/registry_scenarios.json"
HISTORY_PATH = ROOT / "artifacts/section_10_13/bd-y7lu/revocation_head_history.json"
CONFORMANCE_PATH = ROOT / "tests/conformance/revocation_head_monotonicity.rs"
SPEC_PATH = ROOT / "docs/specs/section_10_13/bd-y7lu_contract.md"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-y7lu/verification_evidence.json"
JSON_DECODER = json.JSONDecoder()


def read_utf8(path: Path) -> str | None:
    """Read a UTF-8 text file and return None for missing/unreadable paths."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def load_json_object(path: Path) -> tuple[dict[str, object] | None, str | None]:
    """Load a JSON object and return an explanatory error for invalid artifacts."""
    try:
        raw = path.read_text(encoding="utf-8")
        parsed = JSON_DECODER.decode(raw)
    except OSError as exc:
        return None, f"unable to read {path}: {exc}"
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON in {path}: {exc}"

    if not isinstance(parsed, dict):
        return None, f"expected JSON object in {path}"
    return parsed, None


def record_check(
    checks: list[dict[str, str]],
    check_id: str,
    description: str,
    status: str,
    details: str | None = None,
    *,
    emit_human: bool,
) -> bool:
    entry = {"id": check_id, "description": description, "status": status}
    if details:
        entry["details"] = details
    checks.append(entry)
    if emit_human:
        print(f"  [{status}] {check_id}: {description}")
        if details:
            print(f"         {details}")
    return status == "PASS"


def check(
    checks: list[dict[str, str]],
    check_id: str,
    description: str,
    passed: bool,
    details: str | None = None,
    *,
    emit_human: bool,
) -> bool:
    return record_check(
        checks,
        check_id,
        description,
        "PASS" if passed else "FAIL",
        details,
        emit_human=emit_human,
    )


def run_rust_tests() -> tuple[bool, str]:
    try:
        result = subprocess.run(
            [
                "rch",
                "exec",
                "--",
                "cargo",
                "test",
                "-p",
                "frankenengine-node",
                "--",
                "supply_chain::revocation_registry",
            ],
            capture_output=True,
            text=True,
            timeout=3600,
            cwd=ROOT / "crates/franken-node",
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return False, str(exc)

    test_output = result.stdout + result.stderr
    matches = re.findall(r"test result: ok\. (\d+) passed", test_output)
    rust_tests = sum(int(match) for match in matches)
    tests_pass = result.returncode == 0 and rust_tests > 0
    return tests_pass, f"{rust_tests} tests passed"


def build_evidence(checks: list[dict[str, str]], mode: str) -> dict[str, object]:
    passing = sum(1 for check_entry in checks if check_entry["status"] == "PASS")
    failing = sum(1 for check_entry in checks if check_entry["status"] == "FAIL")
    skipped = sum(1 for check_entry in checks if check_entry["status"] == "SKIP")
    total = len(checks)
    return {
        "gate": "revocation_registry_verification",
        "bead": "bd-y7lu",
        "section": "10.13",
        "mode": mode,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "checks": checks,
        "summary": {
            "total_checks": total,
            "passing_checks": passing,
            "failing_checks": failing,
            "skipped_checks": skipped,
        },
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit evidence JSON to stdout")
    parser.add_argument(
        "--run-rust-tests",
        action="store_true",
        help="run the expensive rch cargo test proof even in JSON mode",
    )
    parser.add_argument(
        "--structural-only",
        action="store_true",
        help="skip the expensive Rust test proof and only validate checked-in structure",
    )
    parser.add_argument(
        "--write-evidence",
        action="store_true",
        help="write artifacts/section_10_13/bd-y7lu/verification_evidence.json; human mode writes by default",
    )
    args = parser.parse_args(argv)
    if args.run_rust_tests and args.structural_only:
        parser.error("--run-rust-tests and --structural-only are mutually exclusive")
    return args


def run_checks(*, run_tests: bool, emit_human: bool) -> dict[str, object]:
    checks: list[dict[str, str]] = []
    if emit_human:
        print("bd-y7lu: Revocation Registry - Verification\n")

    content = read_utf8(IMPL_PATH)
    impl_exists = content is not None
    if content is not None:
        has_head = "struct RevocationHead" in content
        has_registry = "struct RevocationRegistry" in content
        has_error = "enum RevocationError" in content
        has_advance = "fn advance_head" in content
        has_recover = "fn recover_from_log" in content
        has_revoked = "fn is_revoked" in content
        all_types = has_head and has_registry and has_error and has_advance and has_recover and has_revoked
    else:
        all_types = False
    check(
        checks,
        "RR-IMPL",
        "Implementation with all required types and methods",
        impl_exists and all_types,
        emit_human=emit_human,
    )

    if content is not None:
        errors = ["REV_STALE_HEAD", "REV_ZONE_NOT_FOUND", "REV_RECOVERY_FAILED"]
        found = [error_code for error_code in errors if error_code in content]
        check(
            checks,
            "RR-ERRORS",
            "All 3 error codes present",
            len(found) == 3,
            f"found {len(found)}/3",
            emit_human=emit_human,
        )
    else:
        check(checks, "RR-ERRORS", "Error codes", False, emit_human=emit_human)

    fixture_valid = False
    fixture_details = None
    fixture_data, fixture_error = load_json_object(FIXTURE_PATH)
    if fixture_data is not None:
        cases = fixture_data.get("cases")
        fixture_valid = isinstance(cases, list) and len(cases) >= 4
        fixture_details = f"found {len(cases) if isinstance(cases, list) else 0} cases"
    elif fixture_error:
        fixture_details = fixture_error
    check(
        checks,
        "RR-FIXTURES",
        "Registry scenarios fixture",
        fixture_valid,
        fixture_details,
        emit_human=emit_human,
    )

    history_valid = False
    history_details = None
    history_data, history_error = load_json_object(HISTORY_PATH)
    if history_data is not None:
        zones = history_data.get("zones")
        if isinstance(zones, (dict, list)):
            zone_count = len(zones)
        else:
            zone_count = 0
        history_valid = zone_count >= 2
        history_details = f"found {zone_count} zones"
    elif history_error:
        history_details = history_error
    check(
        checks,
        "RR-HISTORY",
        "Revocation head history artifact",
        history_valid,
        history_details,
        emit_human=emit_human,
    )

    conformance_content = read_utf8(CONFORMANCE_PATH)
    conf_exists = conformance_content is not None
    if conformance_content is not None:
        has_monotonic = "inv_rev_monotonic" in conformance_content
        has_stale = "inv_rev_stale" in conformance_content
        has_recoverable = "inv_rev_recoverable" in conformance_content
        has_isolated = "inv_rev_zone_isolated" in conformance_content
    else:
        has_monotonic = has_stale = has_recoverable = has_isolated = False
    check(
        checks,
        "RR-CONF-TESTS",
        "Conformance tests cover all 4 invariants",
        conf_exists and has_monotonic and has_stale and has_recoverable and has_isolated,
        emit_human=emit_human,
    )

    if run_tests:
        tests_pass, details = run_rust_tests()
        check(
            checks,
            "RR-TESTS",
            "Rust unit tests pass",
            tests_pass,
            details,
            emit_human=emit_human,
        )
    else:
        record_check(
            checks,
            "RR-TESTS",
            "Rust unit tests pass",
            "SKIP",
            "not run in structural mode; use --run-rust-tests for the full proof",
            emit_human=emit_human,
        )

    spec_content = read_utf8(SPEC_PATH)
    spec_exists = spec_content is not None
    if spec_content is not None:
        has_invariants = "INV-REV" in spec_content
        has_types = "RevocationHead" in spec_content and "RevocationRegistry" in spec_content
    else:
        has_invariants = has_types = False
    check(
        checks,
        "RR-SPEC",
        "Specification with invariants and types",
        spec_exists and has_invariants and has_types,
        emit_human=emit_human,
    )

    evidence = build_evidence(checks, "full" if run_tests else "structural")
    if emit_human:
        summary = evidence["summary"]
        print(
            f"\nResult: {summary['passing_checks']}/{summary['total_checks']} checks passed"
            f" ({summary['skipped_checks']} skipped)"
        )
    return evidence


def write_evidence(path: Path, evidence: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    run_tests = args.run_rust_tests or (not args.json and not args.structural_only)
    write_artifact = args.write_evidence or not args.json
    logger = configure_test_logging("check_revocation_registry")
    logger.info(
        "starting verification",
        extra={"json_mode": args.json, "run_rust_tests": run_tests, "write_evidence": write_artifact},
    )

    evidence = run_checks(run_tests=run_tests, emit_human=not args.json)

    if write_artifact:
        write_evidence(EVIDENCE_PATH, evidence)

    if args.json:
        print(json.dumps(evidence, indent=2))

    return 0 if evidence["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
