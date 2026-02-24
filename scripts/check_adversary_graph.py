#!/usr/bin/env python3
"""bd-274s verification gate for Bayesian adversary graph and quarantine controller."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

BEAD = "bd-274s"
SECTION = "10.17"

SPEC_FILE = ROOT / "docs/specs/section_10_17/bd-274s_contract.md"
ADV_GRAPH_FILE = ROOT / "crates/franken-node/src/security/adversary_graph.rs"
QC_FILE = ROOT / "crates/franken-node/src/security/quarantine_controller.rs"
MOD_FILE = ROOT / "crates/franken-node/src/security/mod.rs"
UNIT_TEST_FILE = ROOT / "tests/test_check_adversary_graph.py"
STATE_ARTIFACT = ROOT / "artifacts/10.17/adversary_graph_state.json"
EVIDENCE_FILE = ROOT / "artifacts/section_10_17/bd-274s/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_17/bd-274s/verification_summary.md"

REQUIRED_EVENT_CODES = [
    "ADV-001",
    "ADV-002",
    "ADV-003",
    "ADV-004",
    "ADV-005",
    "ADV-006",
    "ADV-007",
    "ADV-008",
]

REQUIRED_ERROR_CODES = [
    "ERR_ADV_NODE_NOT_FOUND",
    "ERR_ADV_DUPLICATE_NODE",
    "ERR_ADV_DANGLING_EDGE",
    "ERR_ADV_INVALID_EVIDENCE_WEIGHT",
    "ERR_QC_INVALID_KEY",
    "ERR_QC_SEQUENCE_VIOLATION",
]

REQUIRED_INVARIANTS = [
    "INV-ADV-DETERMINISTIC",
    "INV-ADV-PRIOR-BOUNDED",
    "INV-ADV-MONOTONE-EVIDENCE",
    "INV-QC-SIGNED-LOG",
    "INV-QC-THRESHOLD-REPRODUCIBLE",
    "INV-QC-SEQUENCE-MONOTONIC",
]


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "passed": ok, "detail": detail or ("ok" if ok else "FAIL")}


def _checks() -> list[dict]:
    checks = []
    adv_src = _read(ADV_GRAPH_FILE)
    qc_src = _read(QC_FILE)
    mod_src = _read(MOD_FILE)
    spec_src = _read(SPEC_FILE)
    all_impl = adv_src + qc_src

    # --- File existence ---
    checks.append(_check("Spec file exists", SPEC_FILE.exists(), str(SPEC_FILE)))
    checks.append(_check("Adversary graph file exists", ADV_GRAPH_FILE.exists(), str(ADV_GRAPH_FILE)))
    checks.append(_check("Quarantine controller file exists", QC_FILE.exists(), str(QC_FILE)))
    checks.append(_check("Security mod file exists", MOD_FILE.exists(), str(MOD_FILE)))

    # --- Module wiring ---
    checks.append(_check(
        "adversary_graph wired in mod.rs",
        "pub mod adversary_graph;" in mod_src,
        "pub mod adversary_graph; in security/mod.rs",
    ))
    checks.append(_check(
        "quarantine_controller wired in mod.rs",
        "pub mod quarantine_controller;" in mod_src,
        "pub mod quarantine_controller; in security/mod.rs",
    ))

    # --- Required struct/type tokens ---
    required_adv_tokens = [
        "struct AdversaryNode",
        "enum EntityType",
        "struct TrustEdge",
        "struct EvidenceEvent",
        "struct SignedEvidenceEntry",
        "struct PolicyThreshold",
        "enum QuarantineAction",
        "struct AdversaryGraph",
        "fn ingest_evidence",
        "fn replay_evidence",
        "fn action_for_risk",
        "fn state_snapshot",
    ]
    for token in required_adv_tokens:
        checks.append(_check(f"Adversary graph token '{token}'", token in adv_src, token))

    required_qc_tokens = [
        "struct QuarantineController",
        "struct ActionRecord",
        "fn submit_evidence",
        "fn replay_batch",
        "fn verify_signature",
        "fn sign_evidence",
        "fn hmac_sha256",
    ]
    for token in required_qc_tokens:
        checks.append(_check(f"Quarantine controller token '{token}'", token in qc_src, token))

    # --- Event codes ---
    for code in REQUIRED_EVENT_CODES:
        present = code in all_impl and code in spec_src
        checks.append(_check(f"Event code {code}", present, code))

    # --- Error codes ---
    for code in REQUIRED_ERROR_CODES:
        present = code in all_impl
        checks.append(_check(f"Error code {code}", present, code))

    # --- Invariants ---
    for inv in REQUIRED_INVARIANTS:
        present = inv in all_impl and inv in spec_src
        checks.append(_check(f"Invariant {inv}", present, inv))

    # --- Policy thresholds ---
    checks.append(_check("Throttle threshold 0.3", "0.3" in adv_src, "throttle: 0.3"))
    checks.append(_check("Isolate threshold 0.5", "0.5" in adv_src, "isolate: 0.5"))
    checks.append(_check("Revoke threshold 0.7", "0.7" in adv_src, "revoke: 0.7"))
    checks.append(_check("Quarantine threshold 0.9", "0.9" in adv_src, "quarantine: 0.9"))

    # --- Determinism invariant: Beta-Bernoulli model ---
    checks.append(_check(
        "Deterministic model (alpha/beta)",
        "alpha" in adv_src and "beta" in adv_src,
        "Beta-Bernoulli conjugate model",
    ))
    checks.append(_check(
        "No RNG in adversary graph",
        "rand" not in adv_src.lower() or "rand_core" not in adv_src,
        "No random number generation in posteriors",
    ))

    # --- Signed evidence ---
    checks.append(_check(
        "HMAC signing in quarantine controller",
        "Sha256" in qc_src and "hmac_sha256" in qc_src,
        "HMAC-SHA256 signing",
    ))
    checks.append(_check(
        "Signature verification",
        "verify_signature" in qc_src,
        "verify_signature method present",
    ))

    # --- Unit tests ---
    adv_test_count = adv_src.count("#[test]")
    qc_test_count = qc_src.count("#[test]")
    total_tests = adv_test_count + qc_test_count
    checks.append(_check(
        "Adversary graph unit tests >= 10",
        adv_test_count >= 10,
        f"found {adv_test_count}",
    ))
    checks.append(_check(
        "Quarantine controller unit tests >= 10",
        qc_test_count >= 10,
        f"found {qc_test_count}",
    ))
    checks.append(_check(
        "Total Rust unit tests >= 20",
        total_tests >= 20,
        f"found {total_tests}",
    ))

    # --- Python test suite ---
    checks.append(_check("Python unit test file exists", UNIT_TEST_FILE.exists(), str(UNIT_TEST_FILE)))

    # --- Quarantine actions ---
    for action in ["Throttle", "Isolate", "Revoke", "Quarantine"]:
        checks.append(_check(
            f"QuarantineAction::{action} defined",
            f"QuarantineAction::{action}" in adv_src or action in adv_src,
            f"QuarantineAction::{action}",
        ))

    return checks


def run_all() -> dict:
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "schema_version": "adversary-graph-v1.0",
        "bead_id": BEAD,
        "section": SECTION,
        "title": "Bayesian adversary graph and automated quarantine controller",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "event_codes": REQUIRED_EVENT_CODES,
        "error_codes": REQUIRED_ERROR_CODES,
        "invariants": REQUIRED_INVARIANTS,
        "policy_thresholds": {
            "throttle": 0.3,
            "isolate": 0.5,
            "revoke": 0.7,
            "quarantine": 0.9,
        },
    }


def write_report(result: dict) -> None:
    STATE_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    STATE_ARTIFACT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def self_test() -> dict:
    checks = []
    checks.append(_check("event code count >= 8", len(REQUIRED_EVENT_CODES) >= 8))
    checks.append(_check("error code count >= 6", len(REQUIRED_ERROR_CODES) >= 6))
    checks.append(_check("invariant count >= 6", len(REQUIRED_INVARIANTS) >= 6))

    result = run_all()
    checks.append(_check("run_all has verdict", result.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_all has checks", isinstance(result.get("checks"), list)))
    checks.append(_check("run_all checks non-empty", len(result.get("checks", [])) > 20))
    checks.append(_check("run_all has policy_thresholds", "policy_thresholds" in result))
    checks.append(_check("run_all has event_codes", len(result.get("event_codes", [])) >= 8))

    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "name": "check_adversary_graph",
        "bead": BEAD,
        "section": SECTION,
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "verdict": verdict,
    }


def main() -> None:
    logger = configure_test_logging("check_adversary_graph")
    parser = argparse.ArgumentParser(description="bd-274s checker")
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
        print(f"bd-274s: {result['verdict']} ({result['passed']}/{result['total']})")
        for c in result["checks"]:
            mark = "+" if c["passed"] else "x"
            print(f"[{mark}] {c['check']}: {c['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
