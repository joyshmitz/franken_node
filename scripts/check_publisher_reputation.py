#!/usr/bin/env python3
"""Verification script for bd-ml1 publisher reputation model."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC_PATH = ROOT / "docs/specs/section_10_4/bd-ml1_contract.md"
RUST_IMPL_PATH = ROOT / "crates/franken-node/src/supply_chain/reputation.rs"
MOD_PATH = ROOT / "crates/franken-node/src/supply_chain/mod.rs"

EVIDENCE_DIR = ROOT / "artifacts/section_10_4/bd-ml1"
EVIDENCE_PATH = EVIDENCE_DIR / "verification_evidence.json"
SUMMARY_PATH = EVIDENCE_DIR / "verification_summary.md"

REQUIRED_INVARIANTS = [
    "INV-REP-DETERMINISTIC",
    "INV-REP-EXPLAINABLE",
    "INV-REP-DECAY",
    "INV-REP-TIERS",
    "INV-REP-FREEZE",
    "INV-REP-RECOVERY",
    "INV-REP-AUDIT",
    "INV-REP-EVENTS",
]

REQUIRED_RUST_SYMBOLS = [
    "pub enum ReputationTier",
    "pub enum SignalKind",
    "pub struct ReputationSignal",
    "pub struct DecayConfig",
    "pub struct TransitionExplanation",
    "pub struct AuditEntry",
    "pub enum AuditEvent",
    "pub struct PublisherReputation",
    "pub struct ReputationRegistry",
    "pub struct RecoveryAction",
    "pub fn deterministic_score",
    "pub fn recovery_actions_for_tier",
]

REQUIRED_EVENT_CODES = [
    "REPUTATION_COMPUTED",
    "REPUTATION_TRANSITION",
    "REPUTATION_FROZEN",
    "REPUTATION_UNFROZEN",
    "REPUTATION_DECAY_APPLIED",
    "REPUTATION_SIGNAL_INGESTED",
    "REPUTATION_RECOVERY_STARTED",
    "REPUTATION_AUDIT_QUERIED",
]

REQUIRED_TIERS = [
    "Suspended",
    "Untrusted",
    "Provisional",
    "Established",
    "Trusted",
]

REQUIRED_SIGNAL_KINDS = [
    "ProvenanceConsistency",
    "VulnerabilityResponseTime",
    "RevocationEvent",
    "ExtensionQuality",
    "CommunityReport",
    "CertificationAdherence",
    "CertificationLapse",
    "QuarantineEvent",
    "QuarantineResolution",
]

REQUIRED_REGISTRY_METHODS = [
    "pub fn register_publisher",
    "pub fn get_reputation",
    "pub fn query_audit_trail",
    "pub fn query_audit_trail_range",
    "pub fn ingest_signal",
    "pub fn apply_decay",
    "pub fn freeze",
    "pub fn unfreeze",
    "pub fn start_recovery",
    "pub fn verify_audit_integrity",
    "pub fn publisher_count",
    "pub fn audit_trail_len",
    "pub fn list_publishers",
]

REQUIRED_TESTS = [
    "test_tier_from_score",
    "test_new_publisher_starts_provisional",
    "test_ingest_positive_signal",
    "test_ingest_negative_signal",
    "test_score_clamped_to_range",
    "test_duplicate_signal_rejected",
    "test_frozen_rejects_signals",
    "test_freeze_unfreeze_cycle",
    "test_decay_reduces_score_toward_baseline",
    "test_decay_skipped_below_min_interval",
    "test_audit_trail_integrity",
    "test_deterministic_scoring",
    "test_tier_transitions_across_boundaries",
    "test_recovery_actions_for_tiers",
    "test_multiple_publishers_isolated",
    "test_weight_override",
    "test_audit_query_by_publisher",
    "test_frozen_rejects_decay",
]


def check_file_exists(path: Path) -> dict[str, Any]:
    """Check that a required file exists and return status."""
    exists = path.exists()
    return {
        "path": str(path.relative_to(ROOT)),
        "exists": exists,
        "size_bytes": path.stat().st_size if exists else 0,
    }


def check_spec_invariants() -> dict[str, Any]:
    """Verify all required invariants appear in the spec document."""
    if not SPEC_PATH.exists():
        return {"pass": False, "reason": "spec file not found", "found": [], "missing": REQUIRED_INVARIANTS}

    content = SPEC_PATH.read_text()
    found = [inv for inv in REQUIRED_INVARIANTS if inv in content]
    missing = [inv for inv in REQUIRED_INVARIANTS if inv not in content]
    return {"pass": len(missing) == 0, "found": found, "missing": missing}


def check_rust_symbols() -> dict[str, Any]:
    """Verify all required Rust symbols exist in the implementation."""
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found", "found": [], "missing": REQUIRED_RUST_SYMBOLS}

    content = RUST_IMPL_PATH.read_text()
    found = [sym for sym in REQUIRED_RUST_SYMBOLS if sym in content]
    missing = [sym for sym in REQUIRED_RUST_SYMBOLS if sym not in content]
    return {"pass": len(missing) == 0, "found": found, "missing": missing}


def check_event_codes() -> dict[str, Any]:
    """Verify all required event codes are defined."""
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found", "found": [], "missing": REQUIRED_EVENT_CODES}

    content = RUST_IMPL_PATH.read_text()
    found = [code for code in REQUIRED_EVENT_CODES if code in content]
    missing = [code for code in REQUIRED_EVENT_CODES if code not in content]
    return {"pass": len(missing) == 0, "found": found, "missing": missing}


def check_tiers() -> dict[str, Any]:
    """Verify all reputation tiers are implemented."""
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found", "found": [], "missing": REQUIRED_TIERS}

    content = RUST_IMPL_PATH.read_text()
    found = [t for t in REQUIRED_TIERS if t in content]
    missing = [t for t in REQUIRED_TIERS if t not in content]
    return {"pass": len(missing) == 0, "found": found, "missing": missing}


def check_signal_kinds() -> dict[str, Any]:
    """Verify all signal kinds are implemented."""
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found", "found": [], "missing": REQUIRED_SIGNAL_KINDS}

    content = RUST_IMPL_PATH.read_text()
    found = [sk for sk in REQUIRED_SIGNAL_KINDS if sk in content]
    missing = [sk for sk in REQUIRED_SIGNAL_KINDS if sk not in content]
    return {"pass": len(missing) == 0, "found": found, "missing": missing}


def check_registry_methods() -> dict[str, Any]:
    """Verify all required ReputationRegistry methods exist."""
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found", "found": [], "missing": REQUIRED_REGISTRY_METHODS}

    content = RUST_IMPL_PATH.read_text()
    found = [m for m in REQUIRED_REGISTRY_METHODS if m in content]
    missing = [m for m in REQUIRED_REGISTRY_METHODS if m not in content]
    return {"pass": len(missing) == 0, "found": found, "missing": missing}


def check_tests() -> dict[str, Any]:
    """Verify all required test functions exist."""
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found", "found": [], "missing": REQUIRED_TESTS}

    content = RUST_IMPL_PATH.read_text()
    found = [t for t in REQUIRED_TESTS if t in content]
    missing = [t for t in REQUIRED_TESTS if t not in content]
    return {"pass": len(missing) == 0, "found": found, "missing": missing}


def check_mod_registration() -> dict[str, Any]:
    """Verify the module is registered in mod.rs."""
    if not MOD_PATH.exists():
        return {"pass": False, "reason": "mod.rs not found"}

    content = MOD_PATH.read_text()
    has_module = "pub mod reputation;" in content
    return {"pass": has_module, "registered": has_module}


def check_determinism() -> dict[str, Any]:
    """Verify deterministic scoring property by checking code patterns."""
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found"}

    content = RUST_IMPL_PATH.read_text()
    has_deterministic_fn = "pub fn deterministic_score" in content
    has_clamp = ".clamp(0.0, 100.0)" in content
    has_btreemap = "BTreeMap" in content  # Deterministic ordering
    return {
        "pass": has_deterministic_fn and has_clamp and has_btreemap,
        "deterministic_fn": has_deterministic_fn,
        "score_clamped": has_clamp,
        "ordered_collections": has_btreemap,
    }


def check_hash_chain() -> dict[str, Any]:
    """Verify hash-chain audit trail implementation."""
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found"}

    content = RUST_IMPL_PATH.read_text()
    has_prev_hash = "prev_hash" in content
    has_entry_hash = "entry_hash" in content
    has_sha256 = "Sha256" in content
    has_verify = "verify_audit_integrity" in content
    return {
        "pass": all([has_prev_hash, has_entry_hash, has_sha256, has_verify]),
        "prev_hash_field": has_prev_hash,
        "entry_hash_field": has_entry_hash,
        "sha256_hashing": has_sha256,
        "integrity_verification": has_verify,
    }


def check_freeze_semantics() -> dict[str, Any]:
    """Verify freeze/unfreeze semantics are implemented."""
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found"}

    content = RUST_IMPL_PATH.read_text()
    has_freeze = "pub fn freeze" in content
    has_unfreeze = "pub fn unfreeze" in content
    has_frozen_field = "pub frozen: bool" in content
    has_suspended = "ReputationTier::Suspended" in content
    has_rejection = "ReputationFrozen" in content
    return {
        "pass": all([has_freeze, has_unfreeze, has_frozen_field, has_suspended, has_rejection]),
        "freeze_method": has_freeze,
        "unfreeze_method": has_unfreeze,
        "frozen_state_field": has_frozen_field,
        "suspended_tier": has_suspended,
        "frozen_signal_rejection": has_rejection,
    }


def run_all_checks() -> dict[str, Any]:
    """Run all verification checks and return structured evidence."""
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = {
        "files": {
            "spec": check_file_exists(SPEC_PATH),
            "rust_impl": check_file_exists(RUST_IMPL_PATH),
            "mod_rs": check_file_exists(MOD_PATH),
        },
        "spec_invariants": check_spec_invariants(),
        "rust_symbols": check_rust_symbols(),
        "event_codes": check_event_codes(),
        "tiers": check_tiers(),
        "signal_kinds": check_signal_kinds(),
        "registry_methods": check_registry_methods(),
        "tests": check_tests(),
        "mod_registration": check_mod_registration(),
        "determinism": check_determinism(),
        "hash_chain": check_hash_chain(),
        "freeze_semantics": check_freeze_semantics(),
    }

    all_pass = all(
        c.get("pass", c.get("exists", False))
        for c in [
            checks["spec_invariants"],
            checks["rust_symbols"],
            checks["event_codes"],
            checks["tiers"],
            checks["signal_kinds"],
            checks["registry_methods"],
            checks["tests"],
            checks["mod_registration"],
            checks["determinism"],
            checks["hash_chain"],
            checks["freeze_semantics"],
        ]
    )

    file_pass = all(f["exists"] for f in checks["files"].values())

    return {
        "bead_id": "bd-ml1",
        "section": "10.4",
        "title": "Publisher Reputation Model with Explainable Transitions",
        "timestamp": timestamp,
        "overall_pass": all_pass and file_pass,
        "checks": checks,
        "summary": {
            "total_checks": 12,
            "passed": sum(
                1
                for c in [
                    checks["spec_invariants"],
                    checks["rust_symbols"],
                    checks["event_codes"],
                    checks["tiers"],
                    checks["signal_kinds"],
                    checks["registry_methods"],
                    checks["tests"],
                    checks["mod_registration"],
                    checks["determinism"],
                    checks["hash_chain"],
                    checks["freeze_semantics"],
                ]
                if c.get("pass", False)
            )
            + (1 if file_pass else 0),
            "failed": 12
            - sum(
                1
                for c in [
                    checks["spec_invariants"],
                    checks["rust_symbols"],
                    checks["event_codes"],
                    checks["tiers"],
                    checks["signal_kinds"],
                    checks["registry_methods"],
                    checks["tests"],
                    checks["mod_registration"],
                    checks["determinism"],
                    checks["hash_chain"],
                    checks["freeze_semantics"],
                ]
                if c.get("pass", False)
            )
            - (1 if file_pass else 0),
        },
    }


def write_evidence(evidence: dict[str, Any]) -> None:
    """Write verification evidence to artifact directory."""
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2) + "\n")


def write_summary(evidence: dict[str, Any]) -> None:
    """Write human-readable verification summary."""
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

    checks = evidence["checks"]

    for name, result in sorted(checks.items()):
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
    """Self-test: verify the check script itself works correctly."""
    evidence = run_all_checks()
    assert isinstance(evidence, dict), "run_all_checks must return a dict"
    assert "bead_id" in evidence, "evidence must contain bead_id"
    assert "checks" in evidence, "evidence must contain checks"
    assert "summary" in evidence, "evidence must contain summary"
    assert evidence["bead_id"] == "bd-ml1", "bead_id must be bd-ml1"

    # Verify all check categories are present.
    expected_categories = [
        "files", "spec_invariants", "rust_symbols", "event_codes",
        "tiers", "signal_kinds", "registry_methods", "tests",
        "mod_registration", "determinism", "hash_chain", "freeze_semantics",
    ]
    for cat in expected_categories:
        assert cat in evidence["checks"], f"missing check category: {cat}"

    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify bd-ml1 publisher reputation model")
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
        print(f"bd-ml1 verification: {status} ({s['passed']}/{s['total_checks']} checks passed)")

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

    # Write artifacts.
    write_evidence(evidence)
    write_summary(evidence)


if __name__ == "__main__":
    main()
