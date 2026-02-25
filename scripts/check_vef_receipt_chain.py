#!/usr/bin/env python3
"""Verification script for bd-3g4k: VEF receipt hash-chain + checkpoints."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


IMPL = ROOT / "crates" / "franken-node" / "src" / "vef" / "receipt_chain.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "vef" / "mod.rs"
SPEC_DOC = ROOT / "docs" / "specs" / "vef_receipt_chain.md"
SPEC_CONTRACT = ROOT / "docs" / "specs" / "section_10_18" / "bd-3g4k_contract.md"
CONFORMANCE_TEST = ROOT / "tests" / "conformance" / "vef_receipt_chain_integrity.rs"
CONFORMANCE_WRAPPER = ROOT / "crates" / "franken-node" / "tests" / "vef_receipt_chain_integrity.rs"
COMMITMENT_LOG = ROOT / "artifacts" / "10.18" / "vef_receipt_commitment_log.jsonl"
CHECKER_TEST = ROOT / "tests" / "test_check_vef_receipt_chain.py"
EVIDENCE = ROOT / "artifacts" / "section_10_18" / "bd-3g4k" / "verification_evidence.json"
SUMMARY = ROOT / "artifacts" / "section_10_18" / "bd-3g4k" / "verification_summary.md"

REQUIRED_EVENT_CODES = [
    "VEF-CHAIN-001",
    "VEF-CHAIN-002",
    "VEF-CHAIN-003",
    "VEF-CHAIN-ERR-001",
    "VEF-CHAIN-ERR-002",
    "VEF-CHAIN-ERR-003",
    "VEF-CHAIN-ERR-004",
]

REQUIRED_INVARIANTS = [
    "INV-VEF-CHAIN-APPEND-ONLY",
    "INV-VEF-CHAIN-DETERMINISTIC",
    "INV-VEF-CHAIN-CHECKPOINT-REPRODUCIBLE",
    "INV-VEF-CHAIN-FAIL-CLOSED",
]

REQUIRED_IMPL_SYMBOLS = [
    "pub struct ReceiptChainConfig",
    "pub struct ReceiptChainEntry",
    "pub struct ReceiptCheckpoint",
    "pub struct AppendOutcome",
    "pub struct ReceiptChain",
    "pub struct ConcurrentReceiptChain",
    "pub fn append(",
    "pub fn force_checkpoint",
    "pub fn verify_integrity",
    "pub fn verify_entries_and_checkpoints",
    "pub fn resume_from_snapshot",
]

RESULTS: list[dict[str, Any]] = []


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _safe_rel(path: Path) -> str:
    return str(path.relative_to(ROOT)) if str(path).startswith(str(ROOT)) else str(path)


def _check(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append(
        {
            "check": name,
            "pass": bool(passed),
            "detail": detail or ("ok" if passed else "NOT FOUND"),
        }
    )


def _load_json(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def check_file_presence() -> None:
    files = [
        ("impl_exists", IMPL),
        ("mod_exists", MOD_RS),
        ("spec_doc_exists", SPEC_DOC),
        ("spec_contract_exists", SPEC_CONTRACT),
        ("conformance_test_exists", CONFORMANCE_TEST),
        ("conformance_wrapper_exists", CONFORMANCE_WRAPPER),
        ("commitment_log_exists", COMMITMENT_LOG),
        ("checker_test_exists", CHECKER_TEST),
        ("evidence_exists", EVIDENCE),
        ("summary_exists", SUMMARY),
    ]
    for name, path in files:
        _check(name, path.is_file(), _safe_rel(path))


def check_impl_symbols() -> None:
    src = _read(IMPL)
    for symbol in REQUIRED_IMPL_SYMBOLS:
        _check(f"impl_symbol_{symbol}", symbol in src, symbol)

    _check("impl_schema_version", "vef-receipt-chain-v1" in src, "vef-receipt-chain-v1")
    _check("impl_genesis_hash", "GENESIS_PREV_HASH" in src, "GENESIS_PREV_HASH")
    _check("impl_uses_sha256", "Sha256" in src, "Sha256")
    _check("impl_append_only_wording", "append-only" in src, "append-only")
    _check("impl_linearizable_wording", "linearizable" in src, "linearizable")

    for code in REQUIRED_EVENT_CODES:
        _check(f"impl_event_{code}", code in src, code)
    for invariant in REQUIRED_INVARIANTS:
        _check(f"impl_invariant_{invariant}", invariant in src, invariant)

    test_count = src.count("#[test]")
    _check("impl_minimum_unit_tests", test_count >= 10, f"{test_count} tests")


def check_mod_wiring() -> None:
    mod_text = _read(MOD_RS)
    _check("vef_mod_wires_receipt_chain", "pub mod receipt_chain;" in mod_text, "pub mod receipt_chain;")


def check_commitment_log() -> None:
    if not COMMITMENT_LOG.is_file():
        _check("commitment_log_parseable_jsonl", False, "missing file")
        return

    lines = [line.strip() for line in COMMITMENT_LOG.read_text(encoding="utf-8").splitlines() if line.strip()]
    _check("commitment_log_minimum_lines", len(lines) >= 2, str(len(lines)))

    hash_re = re.compile(r"^sha256:[0-9a-f]{64}$")
    parsed: list[dict[str, Any]] = []
    for i, line in enumerate(lines):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as err:
            _check(f"commitment_line_{i}_json", False, str(err))
            continue
        parsed.append(obj)
        _check(f"commitment_line_{i}_json", True, "valid JSON")

        required = [
            "schema_version",
            "checkpoint_id",
            "start_index",
            "end_index",
            "entry_count",
            "chain_head_hash",
            "commitment_hash",
            "created_at_millis",
            "trace_id",
        ]
        missing = [k for k in required if k not in obj]
        _check(
            f"commitment_line_{i}_required_fields",
            not missing,
            "all fields present" if not missing else f"missing: {', '.join(missing)}",
        )
        _check(
            f"commitment_line_{i}_schema_version",
            obj.get("schema_version") == "vef-receipt-chain-v1",
            str(obj.get("schema_version")),
        )
        _check(
            f"commitment_line_{i}_chain_hash_format",
            isinstance(obj.get("chain_head_hash"), str) and bool(hash_re.match(obj.get("chain_head_hash", ""))),
            str(obj.get("chain_head_hash")),
        )
        _check(
            f"commitment_line_{i}_commitment_hash_format",
            isinstance(obj.get("commitment_hash"), str) and bool(hash_re.match(obj.get("commitment_hash", ""))),
            str(obj.get("commitment_hash")),
        )

    for i, obj in enumerate(parsed):
        _check(f"commitment_line_{i}_checkpoint_id", obj.get("checkpoint_id") == i, str(obj.get("checkpoint_id")))
        start = obj.get("start_index")
        end = obj.get("end_index")
        entry_count = obj.get("entry_count")
        valid_range = isinstance(start, int) and isinstance(end, int) and end >= start
        _check(f"commitment_line_{i}_valid_range", valid_range, f"{start}..{end}")
        if valid_range:
            _check(
                f"commitment_line_{i}_entry_count_matches",
                entry_count == (end - start + 1),
                f"entry_count={entry_count}",
            )
        if i > 0:
            prev_end = parsed[i - 1].get("end_index")
            contiguous = isinstance(prev_end, int) and isinstance(start, int) and start == prev_end + 1
            _check(f"commitment_line_{i}_contiguous_start", contiguous, f"start={start} prev_end={prev_end}")


def check_specs_content() -> None:
    doc = _read(SPEC_DOC)
    contract = _read(SPEC_CONTRACT)

    _check("spec_doc_mentions_bead", "bd-3g4k" in doc, "bd-3g4k")
    _check("spec_doc_mentions_schema", "vef-receipt-chain-v1" in doc, "vef-receipt-chain-v1")
    _check("spec_doc_mentions_deterministic_rule", "Deterministic Chain-Link Rule" in doc, "Deterministic Chain-Link Rule")
    _check("spec_doc_mentions_checkpoint_rule", "Checkpoint Commitment Rule" in doc, "Checkpoint Commitment Rule")
    _check("spec_doc_mentions_tamper", "Tamper Detection" in doc, "Tamper Detection")

    _check("contract_mentions_acceptance", "Acceptance Criteria" in contract, "Acceptance Criteria")
    _check("contract_mentions_tamper_classes", "Tamper Classes" in contract, "Tamper Classes")

    for code in REQUIRED_EVENT_CODES:
        _check(f"spec_doc_event_{code}", code in doc or code in contract, code)
    for invariant in REQUIRED_INVARIANTS:
        _check(f"spec_doc_invariant_{invariant}", invariant in doc or invariant in contract, invariant)


def check_conformance_tests() -> None:
    conf = _read(CONFORMANCE_TEST)
    wrapper = _read(CONFORMANCE_WRAPPER)
    _check("conformance_mentions_deterministic", "deterministic" in conf.lower(), "deterministic")
    _check("conformance_mentions_tamper", "tamper" in conf.lower(), "tamper")
    _check("conformance_mentions_resume", "resume" in conf.lower(), "resume")
    _check(
        "conformance_wrapper_mentions_fixture_path",
        "tests/conformance/vef_receipt_chain_integrity.rs" in wrapper,
        "tests/conformance/vef_receipt_chain_integrity.rs",
    )
    _check(
        "conformance_wrapper_uses_manifest_dir",
        "CARGO_MANIFEST_DIR" in wrapper,
        "CARGO_MANIFEST_DIR",
    )


def check_evidence_summary() -> None:
    evidence = _load_json(EVIDENCE)
    if evidence is None:
        _check("evidence_parseable_json", False, "invalid or missing JSON")
    else:
        _check("evidence_parseable_json", True, "valid JSON")
        _check("evidence_bead_id", evidence.get("bead_id") == "bd-3g4k", str(evidence.get("bead_id")))
        _check("evidence_verdict_pass", evidence.get("verdict") == "PASS", str(evidence.get("verdict")))

    summary = _read(SUMMARY)
    _check("summary_mentions_bead", "bd-3g4k" in summary, "bd-3g4k")
    _check("summary_mentions_pass", "PASS" in summary, "PASS")


def run_all() -> dict[str, Any]:
    RESULTS.clear()

    check_file_presence()
    check_impl_symbols()
    check_mod_wiring()
    check_commitment_log()
    check_specs_content()
    check_conformance_tests()
    check_evidence_summary()

    total = len(RESULTS)
    passed = sum(1 for entry in RESULTS if entry["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-3g4k",
        "title": "VEF hash-chained receipt stream with periodic commitment checkpoints",
        "section": "10.18",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": total,
        "passed": passed,
        "failed": failed,
        "checks": RESULTS,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def self_test() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def push(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "pass": bool(ok), "detail": detail or ("ok" if ok else "FAIL")})

    push("event_code_count", len(REQUIRED_EVENT_CODES) == 7, str(len(REQUIRED_EVENT_CODES)))
    push("invariant_count", len(REQUIRED_INVARIANTS) == 4, str(len(REQUIRED_INVARIANTS)))
    push("impl_symbol_count", len(REQUIRED_IMPL_SYMBOLS) >= 10, str(len(REQUIRED_IMPL_SYMBOLS)))

    report = run_all()
    push("run_all_is_dict", isinstance(report, dict), "dict")
    push("run_all_has_checks", isinstance(report.get("checks"), list), "checks list")
    push("run_all_total_matches", report.get("total") == len(report.get("checks", [])), "total vs checks")

    passed = sum(1 for entry in checks if entry["pass"])
    failed = len(checks) - passed
    return {
        "bead_id": "bd-3g4k",
        "mode": "self-test",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    logger = configure_test_logging("check_vef_receipt_chain")
    parser = argparse.ArgumentParser(description="Verify bd-3g4k artifacts")
    parser.add_argument("--json", action="store_true", help="emit JSON result")
    parser.add_argument("--self-test", action="store_true", help="run checker self-test")
    args = parser.parse_args()

    result = self_test() if args.self_test else run_all()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[{result['bead_id']}] {result['verdict']} ({result['passed']}/{result['total']})")
        for check in result["checks"]:
            mark = "PASS" if check["pass"] else "FAIL"
            print(f"- {mark} {check['check']}: {check['detail']}")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
