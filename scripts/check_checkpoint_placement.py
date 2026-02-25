#!/usr/bin/env python3
"""Verification script for bd-93k checkpoint placement contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

CHECKPOINT_RS = ROOT / "crates" / "franken-node" / "src" / "runtime" / "checkpoint.rs"
GUARD_RS = ROOT / "crates" / "franken-node" / "src" / "runtime" / "checkpoint_guard.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "runtime" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_11" / "bd-93k_contract.md"
EVIDENCE = ROOT / "artifacts" / "section_10_11" / "bd-93k" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_11" / "bd-93k" / "verification_summary.md"

REQUIRED_CHECKPOINT_TOKENS = [
    "pub const FN_CK_001_CHECKPOINT_SAVE",
    "pub const FN_CK_008_DECISION_STREAM_APPEND",
    "pub const CHECKPOINT_SAVE",
    "pub trait CheckpointContract",
    "pub trait CheckpointBackend",
    "pub struct CheckpointWriter",
    "pub struct CheckpointRecord",
    "pub struct CheckpointMeta",
    "pub struct CheckpointEvent",
    "pub struct RestoredCheckpoint",
    "fn verify_chain(",
    "fn derive_checkpoint_id(",
    "bounded_mask(cx, cancellation, \"checkpoint_write\"",
]

REQUIRED_GUARD_TOKENS = [
    "pub enum GuardMode",
    "pub struct CheckpointGuardConfig",
    "pub struct CheckpointGuard",
    "pub struct CheckpointContractViolation",
    "pub fn checkpoint(&mut self, iteration_count: u64)",
    "pub fn on_iteration(",
    "CHECKPOINT_MISSING",
    "CHECKPOINT_WARNING",
    "CHECKPOINT_CONTRACT_VIOLATION",
]

REQUIRED_TEST_NAMES = [
    "save_restore_roundtrip",
    "idempotent_checkpoint_id_stability",
    "hash_chain_tamper_is_detected_and_skipped",
    "resume_from_latest_valid_checkpoint",
    "warn_mode_logs_warning_without_abort",
    "strict_mode_aborts_after_two_x_iteration_budget",
    "strict_mode_aborts_after_duration_budget",
]

REQUIRED_EVIDENCE_FIELDS = [
    "checkpoints_written",
    "checkpoints_resumed_from",
    "checkpoint_contract_violations",
    "hash_chain_verifications_passed",
    "avg_iterations_between_checkpoints",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _record(results: list[dict[str, Any]], name: str, passed: bool, detail: str) -> None:
    results.append({"name": name, "passed": passed, "detail": detail})


def _contains_all(text: str, tokens: list[str]) -> tuple[bool, list[str]]:
    missing = [token for token in tokens if token not in text]
    return (len(missing) == 0, missing)


def _check_evidence_fields(evidence: dict[str, Any]) -> tuple[bool, list[str]]:
    metrics = evidence.get("verification_metrics")
    if not isinstance(metrics, dict):
        return False, ["verification_metrics missing or invalid"]
    missing = [field for field in REQUIRED_EVIDENCE_FIELDS if field not in metrics]
    return (len(missing) == 0, missing)


def run_checks(project_root: Path = ROOT) -> tuple[bool, dict[str, Any]]:
    files = {
        "checkpoint_rs_exists": project_root / CHECKPOINT_RS.relative_to(ROOT),
        "checkpoint_guard_rs_exists": project_root / GUARD_RS.relative_to(ROOT),
        "runtime_mod_exists": project_root / MOD_RS.relative_to(ROOT),
        "spec_exists": project_root / SPEC.relative_to(ROOT),
        "evidence_exists": project_root / EVIDENCE.relative_to(ROOT),
        "summary_exists": project_root / SUMMARY.relative_to(ROOT),
    }

    results: list[dict[str, Any]] = []

    for name, path in files.items():
        _record(results, name, path.is_file(), str(path))

    if not all(result["passed"] for result in results):
        payload = {
            "bead_id": "bd-93k",
            "ok": False,
            "results": results,
            "summary": {
                "passed": sum(1 for row in results if row["passed"]),
                "total": len(results),
            },
        }
        return False, payload

    checkpoint_text = _read(files["checkpoint_rs_exists"])
    guard_text = _read(files["checkpoint_guard_rs_exists"])
    mod_text = _read(files["runtime_mod_exists"])
    spec_text = _read(files["spec_exists"])
    summary_text = _read(files["summary_exists"])
    evidence_json = json.loads(_read(files["evidence_exists"]))

    ok, missing = _contains_all(checkpoint_text, REQUIRED_CHECKPOINT_TOKENS)
    _record(
        results,
        "checkpoint_tokens",
        ok,
        "missing: " + ", ".join(missing) if missing else "ok",
    )

    ok, missing = _contains_all(guard_text, REQUIRED_GUARD_TOKENS)
    _record(
        results,
        "guard_tokens",
        ok,
        "missing: " + ", ".join(missing) if missing else "ok",
    )

    ok, missing = _contains_all(checkpoint_text + "\n" + guard_text, REQUIRED_TEST_NAMES)
    _record(
        results,
        "unit_test_presence",
        ok,
        "missing: " + ", ".join(missing) if missing else "ok",
    )

    _record(
        results,
        "runtime_mod_exports",
        "pub mod checkpoint;" in mod_text and "pub mod checkpoint_guard;" in mod_text,
        "runtime/mod.rs must export checkpoint and checkpoint_guard",
    )

    _record(
        results,
        "spec_mentions_invariants",
        "INV-CK-PLACEMENT" in spec_text and "## Structured Events" in spec_text,
        "spec must define invariants and structured events",
    )

    _record(
        results,
        "summary_mentions_event_span",
        "FN-CK-001" in summary_text and "FN-CK-008" in summary_text,
        "summary must mention full FN-CK-001..FN-CK-008 span",
    )

    ev_ok, ev_missing = _check_evidence_fields(evidence_json)
    _record(
        results,
        "evidence_metrics_fields",
        ev_ok,
        "missing: " + ", ".join(ev_missing) if ev_missing else "ok",
    )

    passed = all(result["passed"] for result in results)
    payload = {
        "bead_id": "bd-93k",
        "ok": passed,
        "results": results,
        "summary": {
            "passed": sum(1 for row in results if row["passed"]),
            "total": len(results),
        },
    }
    return passed, payload


def self_test() -> tuple[bool, dict[str, Any]]:
    ok, missing = _contains_all("alpha beta gamma", ["alpha", "gamma"])
    fields_ok, fields_missing = _check_evidence_fields(
        {
            "verification_metrics": {
                "checkpoints_written": 1,
                "checkpoints_resumed_from": 1,
                "checkpoint_contract_violations": 0,
                "hash_chain_verifications_passed": 1,
                "avg_iterations_between_checkpoints": 100,
            }
        }
    )
    passed = ok and not missing and fields_ok and not fields_missing
    return passed, {
        "self_test": "passed" if passed else "failed",
        "token_check_ok": ok,
        "metrics_check_ok": fields_ok,
    }


def main() -> int:
    logger = configure_test_logging("check_checkpoint_placement")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--self-test", action="store_true", help="run script self-test")
    args = parser.parse_args()

    if args.self_test:
        ok, payload = self_test()
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"self-test: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1

    ok, payload = run_checks()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("bd-93k checkpoint-placement verification")
        print(f"status: {'PASS' if ok else 'FAIL'}")
        for row in payload["results"]:
            status = "PASS" if row["passed"] else "FAIL"
            print(f"- {status:4} {row['name']}: {row['detail']}")
        print(f"summary: {payload['summary']['passed']}/{payload['summary']['total']} checks passed")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
