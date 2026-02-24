#!/usr/bin/env python3
"""Verification script for bd-2tua: frankensqlite adapter layer.

Usage:
    python scripts/check_frankensqlite_adapter.py          # human-readable
    python scripts/check_frankensqlite_adapter.py --json    # machine-readable
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

IMPL = ROOT / "tests" / "integration" / "frankensqlite_adapter_conformance.rs"
REPORT = ROOT / "artifacts" / "10.16" / "frankensqlite_adapter_report.json"
MATRIX = ROOT / "artifacts" / "10.16" / "frankensqlite_persistence_matrix.json"
SPEC = ROOT / "docs" / "specs" / "section_10_16" / "bd-2tua_contract.md"

PERSISTENCE_DOMAINS = [
    "fencing_token_state",
    "lease_service_state",
    "lease_quorum_coordination",
    "rollout_state",
    "health_gate_policy_state",
    "control_channel_sequence_window",
    "artifact_journal",
    "tiered_trust_storage",
    "canonical_state_roots",
    "durability_mode_controls",
    "durable_claim_gate_audit",
    "snapshot_policy_state",
    "crdt_merge_state",
    "schema_migration_registry",
    "quarantine_store_state",
    "quarantine_promotion_receipts",
    "retention_policy_state",
    "offline_coverage_metrics",
    "repair_cycle_audit",
    "lease_conflict_audit",
    "lifecycle_transition_cache",
]

EVENT_CODES = [
    "FRANKENSQLITE_ADAPTER_INIT",
    "FRANKENSQLITE_WRITE_SUCCESS",
    "FRANKENSQLITE_WRITE_FAIL",
    "FRANKENSQLITE_CRASH_RECOVERY",
    "FRANKENSQLITE_REPLAY_START",
    "FRANKENSQLITE_REPLAY_MISMATCH",
]

INVARIANTS = [
    "INV-FSA-MAPPED",
    "INV-FSA-TIER",
    "INV-FSA-REPLAY",
    "INV-FSA-SCHEMA",
]

REQUIRED_TYPES = [
    "pub enum SafetyTier",
    "pub enum DurabilityMode",
    "pub enum AdapterError",
    "pub struct PersistenceClass",
    "pub struct AdapterConfig",
    "pub struct ConformanceResult",
    "pub struct AdapterEvent",
    "pub struct FrankensqliteAdapter",
    "pub struct AdapterSummary",
]

REQUIRED_METHODS = [
    "fn register_class(",
    "fn tier1_write(",
    "fn tier1_read(",
    "fn tier1_audit_append(",
    "fn tier1_audit_read(",
    "fn tier2_flush(",
    "fn tier2_latest(",
    "fn tier3_put(",
    "fn tier3_get(",
    "fn tier3_evict(",
    "fn gate_pass(",
    "fn summary(",
    "fn to_report(",
    "fn all(",
    "fn label(",
    "fn requires_replay(",
    "fn for_tier(",
    "fn journal_mode(",
    "fn synchronous(",
]

REQUIRED_TESTS = [
    "test_safety_tier_all_count",
    "test_safety_tier_labels",
    "test_safety_tier_requires_replay",
    "test_safety_tier_display",
    "test_safety_tier_serde_roundtrip",
    "test_durability_mode_labels",
    "test_durability_mode_journal",
    "test_durability_mode_synchronous",
    "test_durability_mode_for_tier",
    "test_durability_mode_display",
    "test_durability_mode_serde_roundtrip",
    "test_canonical_class_count",
    "test_canonical_tier1_count",
    "test_canonical_tier2_count",
    "test_canonical_tier3_count",
    "test_canonical_tier1_tier2_replay",
    "test_canonical_durability_mode_matches_tier",
    "test_canonical_unique_domains",
    "test_canonical_unique_table_names",
    "test_adapter_new_emits_init_event",
    "test_adapter_config_defaults",
    "test_adapter_empty_gate_fails",
    "test_adapter_all_classes_gate_pass",
    "test_adapter_summary",
    "test_adapter_total_tables",
    "test_tier1_write_read_roundtrip",
    "test_tier1_read_missing_key",
    "test_tier1_write_emits_event",
    "test_tier1_write_unknown_domain_fails",
    "test_tier1_audit_append_read",
    "test_tier2_flush_latest",
    "test_tier2_latest_empty",
    "test_tier3_put_get_evict",
    "test_tier3_get_missing",
    "test_take_events_drains",
    "test_event_has_transaction_id",
    "test_report_structure",
    "test_report_pass_verdict",
    "test_report_fail_verdict_empty",
    "test_report_conformance_results_count",
    "test_invariant_constants_defined",
    "test_event_code_constants_defined",
    "test_adapter_error_display",
    "test_adapter_error_serde_roundtrip",
    "test_determinism_same_input_same_report",
    "test_persistence_class_serde_roundtrip",
    "test_adapter_event_serde_roundtrip",
    "test_conformance_result_serde_roundtrip",
]


def check_file(path, label):
    ok = path.exists()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"MISSING: {path}",
    }


def check_content(path, patterns, category):
    results = []
    if not path.exists():
        for p in patterns:
            results.append({"check": f"{category}: {p}", "pass": False, "detail": "file missing"})
        return results
    text = path.read_text()
    for p in patterns:
        found = p in text
        results.append({
            "check": f"{category}: {p}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_impl_test_count():
    if not IMPL.exists():
        return {"check": "conformance test count", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    count = len(re.findall(r"#\[test\]", text))
    ok = count >= 40
    return {
        "check": "conformance test count",
        "pass": ok,
        "detail": f"{count} tests (minimum 40)",
    }


def check_serde_derives():
    if not IMPL.exists():
        return {"check": "Serialize/Deserialize derives", "pass": False, "detail": "impl missing"}
    text = IMPL.read_text()
    has_ser = "Serialize" in text and "Deserialize" in text
    return {
        "check": "Serialize/Deserialize derives",
        "pass": has_ser,
        "detail": "found" if has_ser else "NOT FOUND",
    }


def check_report():
    results = []
    if not REPORT.exists():
        results.append({"check": "report: exists", "pass": False, "detail": "MISSING"})
        return results
    results.append({"check": "report: exists", "pass": True, "detail": "found"})
    try:
        data = json.loads(REPORT.read_text())
    except json.JSONDecodeError:
        results.append({"check": "report: valid JSON", "pass": False, "detail": "invalid JSON"})
        return results
    results.append({"check": "report: valid JSON", "pass": True, "detail": "valid"})

    verdict = data.get("gate_verdict", "")
    results.append({
        "check": "report: gate verdict PASS",
        "pass": verdict == "PASS",
        "detail": verdict,
    })

    cr = data.get("conformance_results", [])
    all_pass = all(r.get("status") == "pass" for r in cr)
    results.append({
        "check": "report: all conformance pass",
        "pass": all_pass,
        "detail": f"{len(cr)} results, all pass" if all_pass else "some failures",
    })

    results.append({
        "check": "report: 21 conformance results",
        "pass": len(cr) == 21,
        "detail": f"{len(cr)} results",
    })

    summary = data.get("summary", {})
    results.append({
        "check": "report: tier1 count = 11",
        "pass": summary.get("tier1_count") == 11,
        "detail": f"tier1_count: {summary.get('tier1_count', '?')}",
    })
    results.append({
        "check": "report: tier2 count = 9",
        "pass": summary.get("tier2_count") == 9,
        "detail": f"tier2_count: {summary.get('tier2_count', '?')}",
    })
    results.append({
        "check": "report: tier3 count = 1",
        "pass": summary.get("tier3_count") == 1,
        "detail": f"tier3_count: {summary.get('tier3_count', '?')}",
    })

    return results


def check_spec():
    results = []
    if not SPEC.exists():
        results.append({"check": "spec doc: exists", "pass": False, "detail": "MISSING"})
        return results
    results.append({"check": "spec doc: exists", "pass": True, "detail": "found"})
    text = SPEC.read_text()
    for section in ["Types", "Methods", "Event Codes", "Invariants", "Acceptance Criteria"]:
        found = section in text
        results.append({
            "check": f"spec doc: section '{section}'",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def check_persistence_domains():
    """Verify all 21 persistence domains appear in the impl."""
    results = []
    if not IMPL.exists():
        for d in PERSISTENCE_DOMAINS:
            results.append({"check": f"domain: {d}", "pass": False, "detail": "impl missing"})
        return results
    text = IMPL.read_text()
    for d in PERSISTENCE_DOMAINS:
        found = d in text
        results.append({
            "check": f"domain: {d}",
            "pass": found,
            "detail": "found" if found else "NOT FOUND",
        })
    return results


def run_checks():
    checks = []

    # File existence
    checks.append(check_file(IMPL, "conformance test"))
    checks.append(check_file(REPORT, "adapter report"))
    checks.append(check_file(MATRIX, "persistence matrix"))
    checks.append(check_file(SPEC, "spec doc"))

    # Test count
    checks.append(check_impl_test_count())

    # Serde
    checks.append(check_serde_derives())

    # Implementation content
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, EVENT_CODES, "event_code"))
    checks.extend(check_content(IMPL, INVARIANTS, "invariant"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))

    # Persistence domains
    checks.extend(check_persistence_domains())

    # Report
    checks.extend(check_report())

    # Spec
    checks.extend(check_spec())

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": "bd-2tua",
        "title": "Frankensqlite adapter layer",
        "section": "10.16",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "test_count": check_impl_test_count()["detail"].split()[0] if IMPL.exists() else 0,
        "summary": {"passing": passing, "failing": failing, "total": passing + failing},
        "checks": checks,
    }


def self_test():
    result = run_checks()
    failing = [c for c in result["checks"] if not c["pass"]]
    return len(failing) == 0, result["checks"]


if __name__ == "__main__":
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        status = "PASS" if result["overall_pass"] else "FAIL"
        print(f"bd-2tua verification: {status} ({result['summary']['passing']}/{result['summary']['total']})")
        for c in result["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["overall_pass"] else 1)
