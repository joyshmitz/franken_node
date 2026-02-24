#!/usr/bin/env python3
"""Verification script for bd-tyr2 control-plane evidence replay gate."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

SPEC_PATH = ROOT / "docs/integration/control_evidence_replay_adoption.md"
RUST_IMPL_PATH = ROOT / "crates/franken-node/src/control_plane/evidence_replay_gate.rs"
MOD_PATH = ROOT / "crates/franken-node/src/control_plane/mod.rs"

EVIDENCE_DIR = ROOT / "artifacts/section_10_15/bd-tyr2"
EVIDENCE_PATH = EVIDENCE_DIR / "verification_evidence.json"
SUMMARY_PATH = EVIDENCE_DIR / "verification_summary.md"

REQUIRED_SPEC_CONTENT = [
    "REPRODUCED",
    "DIVERGED",
    "ERROR",
    "RPL-001",
    "RPL-002",
    "RPL-003",
    "RPL-004",
    "RPL-005",
    "HealthGate",
    "Rollout",
    "Quarantine",
    "Fencing",
]

REQUIRED_RUST_SYMBOLS = [
    "pub enum DecisionType",
    "pub enum ReplayVerdict",
    "pub struct CapturedEvidence",
    "pub struct ReplayResult",
    "pub enum GateDecision",
    "pub struct GateResult",
    "pub struct ReplayLogEntry",
    "pub struct EvidenceReplayGate",
]

REQUIRED_EVENT_CODES = [
    "RPL_001_REPLAY_INITIATED",
    "RPL_002_REPRODUCED",
    "RPL_003_DIVERGED",
    "RPL_004_ERROR",
    "RPL_005_GATE_DECISION",
]

REQUIRED_DECISION_TYPES = [
    "HealthGate",
    "Rollout",
    "Quarantine",
    "Fencing",
]

REQUIRED_GATE_METHODS = [
    "pub fn capture_evidence(",
    "pub fn replay_decision(",
    "pub fn evaluate_gate(",
    "pub fn replay_log(",
    "pub fn evidence_count(",
    "pub fn total_replays(",
    "pub fn total_reproduced(",
    "pub fn total_diverged(",
    "pub fn total_errors(",
]

REQUIRED_TESTS = [
    "test_reproduced_verdict",
    "test_diverged_verdict",
    "test_error_verdict_on_tampered_input",
    "test_gate_pass_all_reproduced",
    "test_gate_fail_on_diverged",
    "test_gate_fail_on_error",
    "test_replay_log_events",
    "test_decision_type_coverage",
    "test_input_hash_deterministic",
    "test_different_inputs_different_hash",
    "test_different_epoch_different_hash",
    "test_evidence_capture_and_count",
    "test_counters",
    "test_gate_decision_log_entry",
]


def check_file_exists(path: Path) -> dict[str, Any]:
    exists = path.exists()
    return {
        "path": str(path.relative_to(ROOT)),
        "exists": exists,
        "size_bytes": path.stat().st_size if exists else 0,
    }


def check_content(name: str, path: Path, required: list[str]) -> dict[str, Any]:
    if not path.exists():
        return {"pass": False, "reason": f"{name} file not found", "found": [], "missing": required}
    content = path.read_text()
    found = [item for item in required if item in content]
    missing = [item for item in required if item not in content]
    return {"pass": len(missing) == 0, "found": found, "missing": missing}


def check_mod_registration() -> dict[str, Any]:
    if not MOD_PATH.exists():
        return {"pass": False, "reason": "mod.rs not found"}
    content = MOD_PATH.read_text()
    has_module = "pub mod evidence_replay_gate;" in content
    return {"pass": has_module, "registered": has_module}


def check_hash_integrity() -> dict[str, Any]:
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found"}
    content = RUST_IMPL_PATH.read_text()
    has_sha256 = "Sha256" in content
    has_compute_hash = "compute_input_hash" in content
    has_hash_verify = "input_hash" in content
    return {
        "pass": all([has_sha256, has_compute_hash, has_hash_verify]),
        "sha256": has_sha256,
        "compute_hash": has_compute_hash,
        "hash_verification": has_hash_verify,
    }


def check_verdict_types() -> dict[str, Any]:
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found"}
    content = RUST_IMPL_PATH.read_text()
    has_reproduced = "Reproduced" in content
    has_diverged = "Diverged" in content
    has_error = "Error {" in content or "Error{" in content
    has_diff = "diff_hash" in content and "diff_size_bytes" in content
    return {
        "pass": all([has_reproduced, has_diverged, has_error, has_diff]),
        "reproduced": has_reproduced,
        "diverged": has_diverged,
        "error": has_error,
        "diff_details": has_diff,
    }


def run_all_checks() -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = {
        "files": {
            "spec": check_file_exists(SPEC_PATH),
            "rust_impl": check_file_exists(RUST_IMPL_PATH),
            "mod_rs": check_file_exists(MOD_PATH),
        },
        "spec_content": check_content("spec", SPEC_PATH, REQUIRED_SPEC_CONTENT),
        "rust_symbols": check_content("rust", RUST_IMPL_PATH, REQUIRED_RUST_SYMBOLS),
        "event_codes": check_content("rust", RUST_IMPL_PATH, REQUIRED_EVENT_CODES),
        "decision_types": check_content("rust", RUST_IMPL_PATH, REQUIRED_DECISION_TYPES),
        "gate_methods": check_content("rust", RUST_IMPL_PATH, REQUIRED_GATE_METHODS),
        "tests": check_content("rust", RUST_IMPL_PATH, REQUIRED_TESTS),
        "mod_registration": check_mod_registration(),
        "hash_integrity": check_hash_integrity(),
        "verdict_types": check_verdict_types(),
    }

    check_results = [
        checks["spec_content"],
        checks["rust_symbols"],
        checks["event_codes"],
        checks["decision_types"],
        checks["gate_methods"],
        checks["tests"],
        checks["mod_registration"],
        checks["hash_integrity"],
        checks["verdict_types"],
    ]

    all_pass = all(c.get("pass", False) for c in check_results)
    file_pass = all(f["exists"] for f in checks["files"].values())
    passed_count = sum(1 for c in check_results if c.get("pass", False)) + (1 if file_pass else 0)

    return {
        "bead_id": "bd-tyr2",
        "section": "10.15",
        "title": "Control-Plane Evidence Replay Gate",
        "timestamp": timestamp,
        "overall_pass": all_pass and file_pass,
        "checks": checks,
        "summary": {
            "total_checks": 10,
            "passed": passed_count,
            "failed": 10 - passed_count,
        },
    }


def write_evidence(evidence: dict[str, Any]) -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n")


def write_summary(evidence: dict[str, Any]) -> None:
    s = evidence["summary"]
    lines = [
        f"# Verification Summary: {evidence['title']}",
        "",
        f"**Bead:** {evidence['bead_id']} | **Section:** {evidence['section']}",
        f"**Timestamp:** {evidence['timestamp']}",
        f"**Overall:** {'PASS' if evidence['overall_pass'] else 'FAIL'}",
        f"**Checks:** {s['passed']}/{s['total_checks']} passed",
        "",
        "## Check Results",
        "",
    ]
    for name, result in sorted(evidence["checks"].items()):
        if name == "files":
            for fname, finfo in result.items():
                status = "PASS" if finfo["exists"] else "FAIL"
                lines.append(f"- **File {fname}:** {status} ({finfo['path']}, {finfo['size_bytes']} bytes)")
        else:
            status = "PASS" if result.get("pass", False) else "FAIL"
            lines.append(f"- **{name}:** {status}")
            if "missing" in result and result["missing"]:
                for m in result["missing"]:
                    lines.append(f"  - Missing: `{m}`")

    lines.extend(["", "## Artifacts", ""])
    lines.append(f"- Spec: `{SPEC_PATH.relative_to(ROOT)}`")
    lines.append(f"- Implementation: `{RUST_IMPL_PATH.relative_to(ROOT)}`")
    lines.append(f"- Evidence: `{EVIDENCE_PATH.relative_to(ROOT)}`")
    lines.append("")
    SUMMARY_PATH.write_text("\n".join(lines) + "\n")


def self_test() -> bool:
    evidence = run_all_checks()
    assert isinstance(evidence, dict)
    assert evidence["bead_id"] == "bd-tyr2"
    assert "checks" in evidence
    assert "summary" in evidence
    expected = [
        "files", "spec_content", "rust_symbols", "event_codes",
        "decision_types", "gate_methods", "tests",
        "mod_registration", "hash_integrity", "verdict_types",
    ]
    for cat in expected:
        assert cat in evidence["checks"], f"missing check: {cat}"
    return True


def main() -> None:
    logger = configure_test_logging("check_evidence_replay_gate")
    parser = argparse.ArgumentParser(description="Verify bd-tyr2 evidence replay gate")
    parser.add_argument("--json", action="store_true", help="Output JSON evidence")
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("self_test passed")
        return

    evidence = run_all_checks()

    if args.json:
        print(json.dumps(evidence, indent=2))
    else:
        s = evidence["summary"]
        status = "PASS" if evidence["overall_pass"] else "FAIL"
        print(f"bd-tyr2 verification: {status} ({s['passed']}/{s['total_checks']} checks passed)")
        for name, result in sorted(evidence["checks"].items()):
            if name == "files":
                for fname, finfo in result.items():
                    sym = "+" if finfo["exists"] else "-"
                    print(f"  [{sym}] file:{fname} {finfo['path']}")
            else:
                sym = "+" if result.get("pass", False) else "-"
                print(f"  [{sym}] {name}")
                if "missing" in result and result["missing"]:
                    for m in result["missing"]:
                        print(f"       missing: {m}")

    write_evidence(evidence)
    write_summary(evidence)


if __name__ == "__main__":
    main()
