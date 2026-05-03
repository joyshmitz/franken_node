#!/usr/bin/env python3
"""Verification script for bd-1vvs: Strict-Plus Isolation Backend."""

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

IMPL_PATH = ROOT / "crates/franken-node/src/security/isolation_backend.rs"
FIXTURE_PATH = ROOT / "fixtures/isolation/backend_selection_scenarios.json"
MATRIX_PATH = ROOT / "artifacts/section_10_13/bd-1vvs/strict_plus_runtime_matrix.csv"
INTEGRATION_PATH = ROOT / "tests/integration/strict_plus_isolation.rs"
SPEC_PATH = ROOT / "docs/specs/section_10_13/bd-1vvs_contract.md"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-1vvs/verification_evidence.json"
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
                "security::isolation_backend",
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
        "gate": "isolation_backend_verification",
        "bead": "bd-1vvs",
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
        help="write artifacts/section_10_13/bd-1vvs/verification_evidence.json; human mode writes by default",
    )
    args = parser.parse_args(argv)
    if args.run_rust_tests and args.structural_only:
        parser.error("--run-rust-tests and --structural-only are mutually exclusive")
    return args


def run_checks(*, run_tests: bool, emit_human: bool) -> dict[str, object]:
    checks: list[dict[str, str]] = []
    if emit_human:
        print("bd-1vvs: Strict-Plus Isolation Backend - Verification\n")

    content = read_utf8(IMPL_PATH)
    impl_exists = content is not None
    if content is not None:
        has_backend = "enum IsolationBackend" in content
        has_caps = "struct PlatformCapabilities" in content
        has_select = "fn select_backend" in content
        has_verify = "fn verify_policy_enforcement" in content
        all_types = has_backend and has_caps and has_select and has_verify
    else:
        all_types = False
    check(
        checks,
        "ISOL-IMPL",
        "Implementation with backends, capabilities, selection, verification",
        impl_exists and all_types,
        emit_human=emit_human,
    )

    if content is not None:
        backends = ["MicroVm", "Hardened", "OsSandbox", "Container"]
        found = [backend for backend in backends if backend in content]
        check(
            checks,
            "ISOL-BACKENDS",
            "All 4 isolation backends defined",
            len(found) == 4,
            f"found {len(found)}/4",
            emit_human=emit_human,
        )
    else:
        check(checks, "ISOL-BACKENDS", "All 4 backends", False, emit_human=emit_human)

    if content is not None:
        errors = ["ISOLATION_BACKEND_UNAVAILABLE", "ISOLATION_PROBE_FAILED",
                  "ISOLATION_INIT_FAILED", "ISOLATION_POLICY_MISMATCH"]
        found = [error_code for error_code in errors if error_code in content]
        check(
            checks,
            "ISOL-ERRORS",
            "All 4 error codes present",
            len(found) == 4,
            f"found {len(found)}/4",
            emit_human=emit_human,
        )
    else:
        check(checks, "ISOL-ERRORS", "All 4 error codes", False, emit_human=emit_human)

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
        "ISOL-FIXTURES",
        "Backend selection fixture with scenarios",
        fixture_valid,
        fixture_details,
        emit_human=emit_human,
    )

    matrix_valid = False
    matrix_details = None
    matrix_content = read_utf8(MATRIX_PATH)
    if matrix_content is not None:
        matrix_valid = "microvm" in matrix_content and "hardened" in matrix_content and "os_sandbox" in matrix_content
        matrix_details = f"found {len([line for line in matrix_content.splitlines() if line.strip()])} non-empty rows"
    else:
        matrix_details = f"unable to read {MATRIX_PATH}"
    check(
        checks,
        "ISOL-MATRIX",
        "Runtime matrix CSV with all backends",
        matrix_valid,
        matrix_details,
        emit_human=emit_human,
    )

    integration_content = read_utf8(INTEGRATION_PATH)
    integ_exists = integration_content is not None
    if integration_content is not None:
        has_e2e = "end_to_end" in integration_content
        has_fallback = "fallback" in integration_content
        has_policy = "policy" in integration_content.lower()
    else:
        has_e2e = has_fallback = has_policy = False
    check(
        checks,
        "ISOL-INTEGRATION",
        "Integration tests with e2e, fallback, policy checks",
        integ_exists and has_e2e and has_fallback and has_policy,
        emit_human=emit_human,
    )

    if run_tests:
        tests_pass, details = run_rust_tests()
        check(
            checks,
            "ISOL-TESTS",
            "Rust unit tests pass",
            tests_pass,
            details,
            emit_human=emit_human,
        )
    else:
        record_check(
            checks,
            "ISOL-TESTS",
            "Rust unit tests pass",
            "SKIP",
            "not run in structural mode; use --run-rust-tests for the full proof",
            emit_human=emit_human,
        )

    spec_content = read_utf8(SPEC_PATH)
    spec_exists = spec_content is not None
    if spec_content is not None:
        has_invariants = "INV-STRICT-PLUS" in spec_content
        has_backends = "microvm" in spec_content and "hardened" in spec_content
    else:
        has_invariants = has_backends = False
    check(
        checks,
        "ISOL-SPEC",
        "Specification with invariants and backend matrix",
        spec_exists and has_invariants and has_backends,
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
    logger = configure_test_logging("check_isolation_backend")
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
