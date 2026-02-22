#!/usr/bin/env python3
"""Section 10.6 verification gate: Performance + Packaging.

Aggregates evidence from all 7 section beads and produces a gate verdict.

Usage:
    python scripts/check_section_10_6_gate.py          # human-readable
    python scripts/check_section_10_6_gate.py --json    # machine-readable
    python scripts/check_section_10_6_gate.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

# Section 10.6 beads
SECTION_BEADS = [
    ("bd-k4s", "Build product-level benchmark suite with secure-extension scenarios"),
    ("bd-3lh", "Add cold-start and p99 latency gates for core workflows"),
    ("bd-38m", "Optimize lockstep harness throughput and memory profile"),
    ("bd-2q5", "Optimize migration scanner throughput for large monorepos"),
    ("bd-3kn", "Add packaging profiles for local/dev/enterprise deployments"),
    ("bd-2pw", "Add artifact signing and checksum verification for releases"),
    ("bd-3q9", "Add release rollback bundles with deterministic restore checks"),
]

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _safe_relative(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


def _evidence_pass(data: dict[str, Any]) -> bool:
    """Check if evidence data indicates PASS. Handles multiple formats."""
    if data.get("verdict") == "PASS":
        return True
    if data.get("overall_pass") is True:
        return True
    return False


# ---------------------------------------------------------------------------
# Bead evidence checks
# ---------------------------------------------------------------------------


def check_bead_evidence(bead_id: str, title: str) -> dict[str, Any]:
    """Check that a bead has evidence with PASS verdict."""
    evidence_path = ROOT / "artifacts" / "section_10_6" / bead_id / "verification_evidence.json"
    if not evidence_path.is_file():
        return _check(f"evidence_{bead_id}", False, f"missing: {_safe_relative(evidence_path)}")
    try:
        data = json.loads(evidence_path.read_text())
        passed = _evidence_pass(data)
        return _check(
            f"evidence_{bead_id}",
            passed,
            f"PASS: {title[:60]}" if passed else f"FAIL: {title[:60]}",
        )
    except (json.JSONDecodeError, KeyError) as e:
        return _check(f"evidence_{bead_id}", False, f"parse error: {e}")


def check_bead_summary(bead_id: str) -> dict[str, Any]:
    """Check that a bead has a verification summary."""
    summary_path = ROOT / "artifacts" / "section_10_6" / bead_id / "verification_summary.md"
    exists = summary_path.is_file()
    return _check(
        f"summary_{bead_id}",
        exists,
        f"exists: {_safe_relative(summary_path)}" if exists else f"missing: {_safe_relative(summary_path)}",
    )


# ---------------------------------------------------------------------------
# Aggregate checks
# ---------------------------------------------------------------------------


def check_all_evidence_present() -> dict[str, Any]:
    count = 0
    for bead_id, _ in SECTION_BEADS:
        evidence_path = ROOT / "artifacts" / "section_10_6" / bead_id / "verification_evidence.json"
        if evidence_path.is_file():
            count += 1
    passed = count == len(SECTION_BEADS)
    return _check(
        "all_evidence_present",
        passed,
        f"{count}/{len(SECTION_BEADS)} beads have evidence",
    )


def check_all_verdicts_pass() -> dict[str, Any]:
    pass_count = 0
    fail_list: list[str] = []
    for bead_id, _ in SECTION_BEADS:
        evidence_path = ROOT / "artifacts" / "section_10_6" / bead_id / "verification_evidence.json"
        if evidence_path.is_file():
            try:
                data = json.loads(evidence_path.read_text())
                if _evidence_pass(data):
                    pass_count += 1
                else:
                    fail_list.append(bead_id)
            except (json.JSONDecodeError, KeyError):
                fail_list.append(bead_id)
        else:
            fail_list.append(bead_id)
    passed = pass_count == len(SECTION_BEADS)
    detail = f"{pass_count}/{len(SECTION_BEADS)} PASS" if passed else f"FAIL: {', '.join(fail_list)}"
    return _check("all_verdicts_pass", passed, detail)


def check_benchmark_suite_exists() -> dict[str, Any]:
    path = ROOT / "crates" / "franken-node" / "src" / "tools" / "benchmark_suite.rs"
    exists = path.is_file()
    return _check("benchmark_suite_impl", exists, f"exists: {_safe_relative(path)}" if exists else "missing")


def check_budgets_config_exists() -> dict[str, Any]:
    path = ROOT / "perf" / "budgets.toml"
    exists = path.is_file()
    return _check("budgets_config", exists, f"exists: {_safe_relative(path)}" if exists else "missing")


def check_packaging_profiles_doc() -> dict[str, Any]:
    path = ROOT / "docs" / "policy" / "packaging_profiles.md"
    exists = path.is_file()
    return _check("packaging_profiles_doc", exists, f"exists: {_safe_relative(path)}" if exists else "missing")


def check_artifact_signing_doc() -> dict[str, Any]:
    path = ROOT / "docs" / "policy" / "artifact_signing_verification.md"
    exists = path.is_file()
    return _check("artifact_signing_doc", exists, f"exists: {_safe_relative(path)}" if exists else "missing")


def check_rollback_bundles_doc() -> dict[str, Any]:
    path = ROOT / "docs" / "policy" / "release_rollback_bundles.md"
    exists = path.is_file()
    return _check("rollback_bundles_doc", exists, f"exists: {_safe_relative(path)}" if exists else "missing")


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------


def run_all_checks() -> list[dict[str, Any]]:
    RESULTS.clear()

    # Per-bead evidence checks
    for bead_id, title in SECTION_BEADS:
        check_bead_evidence(bead_id, title)

    # Per-bead summary checks
    for bead_id, _ in SECTION_BEADS:
        check_bead_summary(bead_id)

    # Aggregate checks
    check_all_evidence_present()
    check_all_verdicts_pass()

    # Key artifact checks
    check_benchmark_suite_exists()
    check_budgets_config_exists()
    check_packaging_profiles_doc()
    check_artifact_signing_doc()
    check_rollback_bundles_doc()

    return RESULTS


def self_test() -> bool:
    results = run_all_checks()
    if not results:
        print("SELF-TEST FAIL: no checks returned", file=sys.stderr)
        return False
    for r in results:
        if not isinstance(r, dict) or not all(k in r for k in ("check", "pass", "detail")):
            print(f"SELF-TEST FAIL: bad result: {r}", file=sys.stderr)
            return False
    print(f"SELF-TEST OK: {len(results)} checks returned", file=sys.stderr)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Section 10.6 verification gate")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(0 if self_test() else 1)

    results = run_all_checks()
    total = len(results)
    passed = sum(1 for r in results if r["pass"])
    failed = total - passed
    overall = failed == 0

    if args.json:
        output = {
            "bead_id": "bd-3p9n",
            "title": "Section 10.6 verification gate: Performance + Packaging",
            "section": "10.6",
            "gate": True,
            "verdict": "PASS" if overall else "FAIL",
            "overall_pass": overall,
            "total": total,
            "passed": passed,
            "failed": failed,
            "section_beads": [b[0] for b in SECTION_BEADS],
            "checks": results,
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"\n  Section 10.6 Gate: {'PASS' if overall else 'FAIL'} ({passed}/{total})\n")
        for r in results:
            mark = "+" if r["pass"] else "x"
            print(f"  [{mark}] {r['check']}: {r['detail']}")

    sys.exit(0 if overall else 1)


if __name__ == "__main__":
    main()
