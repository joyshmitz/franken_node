#!/usr/bin/env python3
"""Section 10.10 verification gate: comprehensive unit+e2e+logging.

Aggregates evidence from all 11 Section 10.10 beads and emits a deterministic
PASS/FAIL verdict for downstream program-wide gates.

Usage:
    python scripts/check_section_10_10_gate.py
    python scripts/check_section_10_10_gate.py --json
    python scripts/check_section_10_10_gate.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path
from typing import Any


SECTION_BEADS = [
    ("bd-1l5", "Canonical product trust object IDs with domain separation"),
    ("bd-jjm", "Canonical deterministic serialization and signature preimage rules"),
    ("bd-174", "Policy checkpoint chain for product release channels"),
    ("bd-2ms", "Rollback/fork detection in control-plane state propagation"),
    ("bd-1r2", "Audience-bound token chains for control actions"),
    ("bd-364", "Key-role separation for control-plane signing/encryption/issuance"),
    ("bd-oty", "Session-authenticated control channel + anti-replay framing"),
    ("bd-2sx", "Revocation freshness semantics before risky/dangerous actions"),
    ("bd-1vp", "Zone/tenant trust segmentation policies"),
    ("bd-13q", "Stable error namespace and compatibility policy"),
    ("bd-1hd", "Canonical trust protocol vectors/golden fixtures as release gates"),
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


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict):
        return data
    return None


def _evidence_pass(data: dict[str, Any]) -> bool:
    """Interpret heterogeneous evidence schemas used across section beads."""
    verdict = str(data.get("verdict", "")).strip().upper()
    if verdict == "PASS":
        return True

    if data.get("overall_pass") is True:
        return True

    status = str(data.get("status", "")).strip().lower()
    if status in {"pass", "passed", "ok", "completed", "completed_with_baseline_workspace_failures"}:
        return True

    # Some reports only include command-level statuses.
    command_results = data.get("command_results")
    if isinstance(command_results, list) and command_results:
        normalized: list[str] = []
        for item in command_results:
            if isinstance(item, dict):
                normalized.append(str(item.get("status", "")).strip().upper())
        if normalized and any(s == "PASS" for s in normalized):
            if all(s in {"PASS", "FAIL_BASELINE"} for s in normalized):
                return True

    return False


def _bead_evidence_path(bead_id: str) -> Path:
    return ROOT / "artifacts" / "section_10_10" / bead_id / "verification_evidence.json"


def _bead_summary_path(bead_id: str) -> Path:
    return ROOT / "artifacts" / "section_10_10" / bead_id / "verification_summary.md"


def _bead_spec_path(bead_id: str) -> Path:
    return ROOT / "docs" / "specs" / "section_10_10" / f"{bead_id}_contract.md"


def check_bead_evidence(bead_id: str, title: str) -> dict[str, Any]:
    evidence_path = _bead_evidence_path(bead_id)
    data = _load_json(evidence_path)
    if data is None:
        return _check(f"evidence_{bead_id}", False, f"missing/invalid: {_safe_relative(evidence_path)}")

    passed = _evidence_pass(data)
    detail = f"PASS: {title[:64]}" if passed else f"FAIL: {title[:64]}"
    return _check(f"evidence_{bead_id}", passed, detail)


def check_bead_summary(bead_id: str) -> dict[str, Any]:
    summary_path = _bead_summary_path(bead_id)
    exists = summary_path.is_file()
    non_empty = exists and summary_path.stat().st_size > 0
    detail = (
        f"exists: {_safe_relative(summary_path)}"
        if non_empty
        else f"missing/empty: {_safe_relative(summary_path)}"
    )
    return _check(f"summary_{bead_id}", non_empty, detail)


def check_bead_spec(bead_id: str) -> dict[str, Any]:
    spec_path = _bead_spec_path(bead_id)
    exists = spec_path.is_file()
    detail = f"exists: {_safe_relative(spec_path)}" if exists else f"missing: {_safe_relative(spec_path)}"
    return _check(f"spec_{bead_id}", exists, detail)


def check_all_evidence_present() -> dict[str, Any]:
    count = sum(1 for bead_id, _ in SECTION_BEADS if _bead_evidence_path(bead_id).is_file())
    return _check("all_evidence_present", count == len(SECTION_BEADS), f"{count}/{len(SECTION_BEADS)} beads have evidence")


def check_all_summaries_present() -> dict[str, Any]:
    count = sum(1 for bead_id, _ in SECTION_BEADS if _bead_summary_path(bead_id).is_file())
    return _check("all_summaries_present", count == len(SECTION_BEADS), f"{count}/{len(SECTION_BEADS)} beads have summaries")


def check_all_specs_present() -> dict[str, Any]:
    count = sum(1 for bead_id, _ in SECTION_BEADS if _bead_spec_path(bead_id).is_file())
    return _check("all_specs_present", count == len(SECTION_BEADS), f"{count}/{len(SECTION_BEADS)} specs present")


def check_all_verdicts_pass() -> dict[str, Any]:
    failing: list[str] = []
    for bead_id, _ in SECTION_BEADS:
        data = _load_json(_bead_evidence_path(bead_id))
        if data is None or not _evidence_pass(data):
            failing.append(bead_id)
    passed = not failing
    detail = "all PASS" if passed else f"failing: {', '.join(failing)}"
    return _check("all_verdicts_pass", passed, detail)


def check_section_bead_cardinality() -> dict[str, Any]:
    return _check("section_bead_cardinality", len(SECTION_BEADS) == 11, f"{len(SECTION_BEADS)} beads configured")


def check_vector_coverage_artifact() -> dict[str, Any]:
    path = ROOT / "artifacts" / "section_10_10" / "bd-1hd" / "vector_coverage.json"
    exists = path.is_file()
    detail = f"exists: {_safe_relative(path)}" if exists else f"missing: {_safe_relative(path)}"
    return _check("vector_coverage_artifact", exists, detail)


def check_error_namespace_audit_artifact() -> dict[str, Any]:
    path = ROOT / "artifacts" / "section_10_10" / "bd-13q" / "error_audit.json"
    exists = path.is_file()
    detail = f"exists: {_safe_relative(path)}" if exists else f"missing: {_safe_relative(path)}"
    return _check("error_namespace_audit_artifact", exists, detail)


def check_trust_object_prefix_coverage() -> dict[str, Any]:
    data = _load_json(_bead_evidence_path("bd-1l5"))
    if data is None:
        return _check("cross_trust_object_prefix_coverage", False, "bd-1l5 evidence missing")

    ac = str(data.get("acceptance_criteria", {}).get("AC1_domain_prefixes", ""))
    expected = ["ext:", "tcard:", "rcpt:", "pchk:", "migr:", "vclaim:"]
    present = [token for token in expected if token in ac]
    passed = len(present) == len(expected)
    return _check(
        "cross_trust_object_prefix_coverage",
        passed,
        f"{len(present)}/{len(expected)} canonical prefixes present",
    )


def check_checkpoint_prefix_alignment() -> dict[str, Any]:
    data = _load_json(_bead_evidence_path("bd-174"))
    if data is None:
        return _check("cross_checkpoint_prefix_alignment", False, "bd-174 evidence missing")

    hashes = data.get("metrics", {}).get("sample_checkpoint_hashes", [])
    if not isinstance(hashes, list) or not hashes:
        return _check("cross_checkpoint_prefix_alignment", False, "sample checkpoint hashes missing")

    prefixed = [h for h in hashes if isinstance(h, str) and h.startswith("pchk:")]
    passed = len(prefixed) == len(hashes)
    return _check("cross_checkpoint_prefix_alignment", passed, f"{len(prefixed)}/{len(hashes)} hashes use pchk: prefix")


def check_token_chain_invariants() -> dict[str, Any]:
    data = _load_json(_bead_evidence_path("bd-1r2"))
    if data is None:
        return _check("cross_token_chain_invariants", False, "bd-1r2 evidence missing")

    checks = data.get("checks", [])
    if not isinstance(checks, list):
        return _check("cross_token_chain_invariants", False, "bd-1r2 checks missing")

    required = {
        "type: pub struct TokenChain",
        "invariant: INV-ABT-ATTENUATION",
        "invariant: INV-ABT-REPLAY",
    }
    found: set[str] = set()
    for item in checks:
        if isinstance(item, dict) and item.get("pass") is True:
            name = str(item.get("check", ""))
            if name in required:
                found.add(name)

    passed = found == required
    return _check("cross_token_chain_invariants", passed, f"{len(found)}/{len(required)} token-chain invariants present")


def check_zone_segmentation_invariants() -> dict[str, Any]:
    data = _load_json(_bead_evidence_path("bd-1vp"))
    if data is None:
        return _check("cross_zone_segmentation_invariants", False, "bd-1vp evidence missing")

    invariants = data.get("invariants", [])
    if not isinstance(invariants, list):
        return _check("cross_zone_segmentation_invariants", False, "bd-1vp invariants missing")

    required = {"INV-ZTS-ISOLATE", "INV-ZTS-CEILING", "INV-ZTS-DEPTH", "INV-ZTS-BIND"}
    present = {inv for inv in invariants if isinstance(inv, str)}
    matched = required.intersection(present)
    passed = matched == required
    return _check("cross_zone_segmentation_invariants", passed, f"{len(matched)}/{len(required)} invariants present")


def check_trust_chain_cross_bead_coherence() -> dict[str, Any]:
    chain = ["bd-1l5", "bd-1r2", "bd-174", "bd-1vp"]
    passing = 0
    for bead_id in chain:
        data = _load_json(_bead_evidence_path(bead_id))
        if data is not None and _evidence_pass(data):
            passing += 1
    passed = passing == len(chain)
    return _check("cross_trust_chain_coherence", passed, f"{passing}/{len(chain)} cross-bead trust-chain components PASS")


def check_session_auth_hardening() -> dict[str, Any]:
    data = _load_json(_bead_evidence_path("bd-oty"))
    if data is None:
        return _check("hardening_session_auth", False, "bd-oty evidence missing")

    ac = data.get("acceptance_criteria", {})
    ac1 = str(ac.get("AC1_session_requirement", "")).lower()
    ac2 = str(ac.get("AC2_sequence_monotonicity", "")).lower()
    metrics = data.get("metrics", {})
    direction_checks = int(metrics.get("direction_integration_checks", 0))
    passed = (
        "active authenticated session" in ac1
        and "per-direction sequence" in ac2
        and direction_checks >= 3
    )
    return _check("hardening_session_auth", passed, f"direction_integration_checks={direction_checks}")


def check_revocation_freshness_hardening() -> dict[str, Any]:
    data = _load_json(_bead_evidence_path("bd-2sx"))
    if data is None:
        return _check("hardening_revocation_freshness", False, "bd-2sx evidence missing")

    v = data.get("verification_checks", {})
    passed = bool(v.get("replay_detection_implemented")) and bool(v.get("signature_verification_implemented")) and bool(v.get("all_tiers_documented"))
    return _check(
        "hardening_revocation_freshness",
        passed,
        (
            "replay/signature/tier checks present"
            if passed
            else "missing replay/signature/tier verification"
        ),
    )


def check_release_gate_vectors_hardening() -> dict[str, Any]:
    data = _load_json(_bead_evidence_path("bd-1hd"))
    if data is None:
        return _check("hardening_release_vectors", False, "bd-1hd evidence missing")
    passed = _evidence_pass(data)
    return _check("hardening_release_vectors", passed, "release vector evidence PASS" if passed else "release vector evidence FAIL")


def check_error_namespace_hardening() -> dict[str, Any]:
    data = _load_json(_bead_evidence_path("bd-13q"))
    if data is None:
        return _check("hardening_error_namespace", False, "bd-13q evidence missing")

    command_results = data.get("command_results", [])
    if not isinstance(command_results, list):
        return _check("hardening_error_namespace", False, "command_results missing")

    has_namespace_pass = False
    for item in command_results:
        if not isinstance(item, dict):
            continue
        command = str(item.get("command", ""))
        status = str(item.get("status", "")).upper()
        summary_verdict = str(item.get("summary", {}).get("verdict", "")).upper()
        if "check_error_namespace.py --json" in command and status == "PASS" and summary_verdict == "PASS":
            has_namespace_pass = True
            break

    return _check("hardening_error_namespace", has_namespace_pass, "namespace compatibility report PASS" if has_namespace_pass else "namespace compatibility report missing/FAIL")


def check_control_plane_surfaces_present() -> dict[str, Any]:
    surfaces = [
        ROOT / "crates" / "franken-node" / "src" / "api" / "session_auth.rs",
        ROOT / "crates" / "franken-node" / "src" / "connector" / "control_channel.rs",
        ROOT / "crates" / "franken-node" / "src" / "security" / "revocation_freshness_gate.rs",
    ]
    present = sum(1 for path in surfaces if path.is_file())
    return _check("hardening_control_plane_surfaces_present", present == len(surfaces), f"{present}/{len(surfaces)} hardening surfaces present")


def check_mod_registration_hardening() -> dict[str, Any]:
    api_mod = ROOT / "crates" / "franken-node" / "src" / "api" / "mod.rs"
    sec_mod = ROOT / "crates" / "franken-node" / "src" / "security" / "mod.rs"
    if not api_mod.is_file() or not sec_mod.is_file():
        return _check("hardening_mod_registration", False, "api/security mod.rs missing")

    api_src = api_mod.read_text()
    sec_src = sec_mod.read_text()
    passed = "pub mod session_auth;" in api_src and "pub mod revocation_freshness_gate;" in sec_src
    return _check("hardening_mod_registration", passed, "session_auth + revocation_freshness_gate registered" if passed else "required mod registrations missing")


def run_all_checks() -> list[dict[str, Any]]:
    RESULTS.clear()

    # Per-bead checks
    for bead_id, title in SECTION_BEADS:
        check_bead_evidence(bead_id, title)
    for bead_id, _ in SECTION_BEADS:
        check_bead_summary(bead_id)
    for bead_id, _ in SECTION_BEADS:
        check_bead_spec(bead_id)

    # Aggregates
    check_section_bead_cardinality()
    check_all_evidence_present()
    check_all_summaries_present()
    check_all_specs_present()
    check_all_verdicts_pass()

    # Section artifacts
    check_vector_coverage_artifact()
    check_error_namespace_audit_artifact()

    # Cross-bead integration checks
    check_trust_object_prefix_coverage()
    check_checkpoint_prefix_alignment()
    check_token_chain_invariants()
    check_zone_segmentation_invariants()
    check_trust_chain_cross_bead_coherence()

    # Hardening coverage checks
    check_session_auth_hardening()
    check_revocation_freshness_hardening()
    check_release_gate_vectors_hardening()
    check_error_namespace_hardening()
    check_control_plane_surfaces_present()
    check_mod_registration_hardening()

    return RESULTS


def run_all() -> dict[str, Any]:
    checks = run_all_checks()
    total = len(checks)
    passed = sum(1 for c in checks if c["pass"])
    failed = total - passed
    overall = failed == 0

    return {
        "bead_id": "bd-1jjq",
        "title": "Section 10.10 verification gate: comprehensive unit+e2e+logging",
        "section": "10.10",
        "gate": True,
        "verdict": "PASS" if overall else "FAIL",
        "overall_pass": overall,
        "total": total,
        "passed": passed,
        "failed": failed,
        "section_beads": [bead_id for bead_id, _ in SECTION_BEADS],
        "checks": checks,
    }


def self_test() -> bool:
    checks = run_all_checks()
    if not checks:
        print("SELF-TEST FAIL: no checks returned", file=sys.stderr)
        return False

    required_keys = {"check", "pass", "detail"}
    for entry in checks:
        if not isinstance(entry, dict) or not required_keys.issubset(entry.keys()):
            print(f"SELF-TEST FAIL: malformed check entry: {entry}", file=sys.stderr)
            return False

    print(f"SELF-TEST OK: {len(checks)} checks returned", file=sys.stderr)
    return True


def main() -> None:
    logger = configure_test_logging("check_section_10_10_gate")
    parser = argparse.ArgumentParser(description="Section 10.10 verification gate")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(0 if self_test() else 1)

    output = run_all()

    if args.json:
        print(json.dumps(output, indent=2))
    else:
        print(
            f"\n  Section 10.10 Gate: {'PASS' if output['overall_pass'] else 'FAIL'} "
            f"({output['passed']}/{output['total']})\n"
        )
        for entry in output["checks"]:
            mark = "+" if entry["pass"] else "x"
            print(f"  [{mark}] {entry['check']}: {entry['detail']}")

    sys.exit(0 if output["overall_pass"] else 1)


if __name__ == "__main__":
    main()
