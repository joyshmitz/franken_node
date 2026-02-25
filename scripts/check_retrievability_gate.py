#!/usr/bin/env python3
"""Verification script for bd-1fck: retrievability-before-eviction proofs."""

import json
import os
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMPL = os.path.join(ROOT, "crates/franken-node/src/storage/retrievability_gate.rs")
MOD_RS = os.path.join(ROOT, "crates/franken-node/src/storage/mod.rs")
MAIN_RS = os.path.join(ROOT, "crates/franken-node/src/main.rs")
SPEC = os.path.join(ROOT, "docs/specs/section_10_14/bd-1fck_contract.md")
RECEIPTS = os.path.join(ROOT, "artifacts/10.14/retrievability_proof_receipts.json")


def _check(name: str, passed: bool, detail: str = "") -> dict:
    return {"check": name, "pass": passed, "detail": detail or ("found" if passed else "NOT FOUND")}


def _file_exists(path: str, label: str) -> dict:
    exists = os.path.isfile(path)
    return _check(f"file: {label}", exists,
                  f"exists: {os.path.relpath(path, ROOT)}" if exists else f"missing: {os.path.relpath(path, ROOT)}")


def run_checks() -> list[dict]:
    checks = []

    # File existence
    checks.append(_file_exists(IMPL, "implementation"))
    checks.append(_file_exists(SPEC, "spec contract"))
    checks.append(_file_exists(RECEIPTS, "proof receipts artifact"))

    # Module registered in storage/mod.rs
    with open(MOD_RS) as f:
        mod_src = f.read()
    checks.append(_check("module registered in storage/mod.rs", "pub mod retrievability_gate;" in mod_src))

    # Storage module registered in main.rs
    with open(MAIN_RS) as f:
        main_src = f.read()
    checks.append(_check("storage module in main.rs", "pub mod storage;" in main_src))

    with open(IMPL) as f:
        src = f.read()

    # Types
    for ty in ["pub struct ArtifactId", "pub struct SegmentId", "pub enum StorageTier",
               "pub enum ProofFailureReason", "pub struct RetrievabilityProof",
               "pub struct RetrievabilityError", "pub struct RetrievabilityConfig",
               "pub struct ProofReceipt", "pub struct GateEvent",
               "pub struct EvictionPermit", "pub struct RetrievabilityGate",
               "pub struct TargetTierState"]:
        checks.append(_check(f"type: {ty}", ty in src))

    # StorageTier variants
    for variant in ["L1Hot", "L2Warm", "L3Archive"]:
        checks.append(_check(f"tier: {variant}", variant in src))

    # ProofFailureReason variants
    for variant in ["HashMismatch", "LatencyExceeded", "TargetUnreachable"]:
        checks.append(_check(f"failure: {variant}", variant in src))

    # Methods
    for method in ["fn check_retrievability(", "fn attempt_eviction(",
                   "fn register_target(", "fn receipts(",
                   "fn events(", "fn config(",
                   "fn passed_count(", "fn failed_count(",
                   "fn receipts_json(", "fn content_hash(",
                   "fn label(", "fn error_code("]:
        checks.append(_check(f"method: {method}", method in src))

    # Event codes
    for code in ["RG_PROOF_PASSED", "RG_PROOF_FAILED", "RG_EVICTION_BLOCKED",
                 "RG_EVICTION_PERMITTED", "RG_GATE_INITIALIZED"]:
        checks.append(_check(f"event_code: {code}", code in src))

    # Error codes
    for code in ["ERR_HASH_MISMATCH", "ERR_LATENCY_EXCEEDED",
                 "ERR_TARGET_UNREACHABLE", "ERR_EVICTION_BLOCKED"]:
        checks.append(_check(f"error_code: {code}", code in src))

    # Invariants
    for inv in ["INV-RG-BLOCK-EVICTION", "INV-RG-PROOF-BINDING",
                "INV-RG-FAIL-CLOSED", "INV-RG-AUDIT-TRAIL"]:
        checks.append(_check(f"invariant: {inv}", inv in src))

    # Serde + SHA-256
    checks.append(_check("serde derives", "Serialize" in src and "Deserialize" in src))
    checks.append(_check("SHA-256 for content hash", "Sha256" in src))

    # Send + Sync
    checks.append(_check("Send + Sync asserted", "assert_send" in src and "assert_sync" in src))

    # ProofReceipt fields
    for field in ["artifact_id", "segment_id", "source_tier", "target_tier",
                  "content_hash", "proof_timestamp", "latency_ms", "passed", "failure_reason"]:
        checks.append(_check(f"receipt_field: {field}", f"{field}:" in src))

    # Tests
    test_names = [
        "test_default_config",
        "test_successful_proof",
        "test_successful_proof_emits_event",
        "test_successful_proof_creates_receipt",
        "test_hash_mismatch_blocks",
        "test_hash_mismatch_emits_failure_event",
        "test_hash_mismatch_records_receipt",
        "test_latency_exceeded_blocks",
        "test_latency_at_limit_passes",
        "test_unreachable_target_blocks",
        "test_unregistered_target_blocks",
        "test_eviction_succeeds_with_proof",
        "test_eviction_blocked_without_proof",
        "test_eviction_blocked_emits_event",
        "test_eviction_permitted_emits_event",
        "test_proof_bound_to_segment",
        "test_proof_bound_to_artifact",
        "test_proof_bound_to_target_tier",
        "test_passed_count",
        "test_failed_count",
        "test_mixed_counts",
        "test_content_hash_deterministic",
        "test_content_hash_different_inputs",
        "test_content_hash_hex_format",
        "test_receipts_json_valid",
        "test_gate_init_event",
        "test_storage_tier_labels",
        "test_failure_reason_error_codes",
        "test_failure_reason_labels",
        "test_error_display",
        "test_proof_serde_roundtrip",
        "test_receipt_serde_roundtrip",
        "test_eviction_permit_serde",
        "test_config_serde_roundtrip",
        "test_event_codes_defined",
        "test_error_codes_defined",
        "test_no_bypass_hash_mismatch",
        "test_no_bypass_latency",
        "test_no_bypass_unreachable",
        "test_multiple_artifacts_independent",
        "test_failure_reason_display",
    ]
    for test in test_names:
        checks.append(_check(f"test: {test}", f"fn {test}(" in src))

    # Unit test count
    test_count = len(re.findall(r"#\[test\]", src))
    checks.append(_check("unit test count", test_count >= 35,
                          f"{test_count} tests (minimum 35)"))

    # Proof receipts artifact content
    if os.path.isfile(RECEIPTS):
        with open(RECEIPTS) as f:
            data = json.load(f)
        receipts_list = data.get("proof_receipts", data.get("receipts", []))
        checks.append(_check("receipts has entries", len(receipts_list) >= 3,
                              f"{len(receipts_list)} receipts (minimum 3)"))
        has_pass = any(r.get("result") == "passed" or r.get("passed") for r in receipts_list)
        has_fail = any(r.get("result") == "failed" or r.get("passed") is False for r in receipts_list)
        checks.append(_check("receipts has passed entry", has_pass))
        checks.append(_check("receipts has failed entry", has_fail))
    else:
        for label in ["receipts has entries", "receipts has passed entry", "receipts has failed entry"]:
            checks.append(_check(label, False, "file missing"))

    return checks


def self_test():
    checks = run_checks()
    total = len(checks)
    passing = sum(1 for c in checks if c["pass"])
    failing = total - passing
    print(f"self_test: {passing}/{total} checks pass, {failing} failing")
    if failing:
        for c in checks:
            if not c["pass"]:
                print(f"  FAIL: {c['check']} — {c['detail']}")
    return failing == 0


def main():
    logger = configure_test_logging("check_retrievability_gate")
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)

    checks = run_checks()
    total = len(checks)
    passing = sum(1 for c in checks if c["pass"])
    failing = total - passing

    test_count = len(re.findall(r"#\[test\]", __import__("pathlib").Path(IMPL).read_text(encoding="utf-8"))) if os.path.isfile(IMPL) else 0

    if args.json:
        result = {
            "bead_id": "bd-1fck",
            "title": "Retrievability-before-eviction proofs",
            "section": "10.14",
            "overall_pass": failing == 0,
            "verdict": "PASS" if failing == 0 else "FAIL",
            "test_count": test_count,
            "summary": {"passing": passing, "failing": failing, "total": total},
            "checks": checks,
        }
        print(json.dumps(result, indent=2))
    else:
        for c in checks:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"[{status}] {c['check']}: {c['detail']}")
        print(f"\n{passing}/{total} checks pass")

    sys.exit(0 if failing == 0 else 1)


if __name__ == "__main__":
    main()
