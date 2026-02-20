#!/usr/bin/env python3
"""Verification script for bd-2yc operator copilot action recommendation API."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC_PATH = ROOT / "docs/specs/section_10_5/bd-2yc_contract.md"
RUST_IMPL_PATH = ROOT / "crates/franken-node/src/security/copilot_engine.rs"
MOD_PATH = ROOT / "crates/franken-node/src/security/mod.rs"

EVIDENCE_DIR = ROOT / "artifacts/section_10_5/bd-2yc"
EVIDENCE_PATH = EVIDENCE_DIR / "verification_evidence.json"
SUMMARY_PATH = EVIDENCE_DIR / "verification_summary.md"

REQUIRED_INVARIANTS = [
    "INV-COP-VOI-RANK",
    "INV-COP-LOSS-VEC",
    "INV-COP-UNCERTAINTY",
    "INV-COP-ROLLBACK",
    "INV-COP-DEGRADED",
    "INV-COP-RATIONALE",
    "INV-COP-AUDIT",
    "INV-COP-TOP-K",
]

REQUIRED_RUST_SYMBOLS = [
    "pub struct ExpectedLossVector",
    "pub struct ConfidenceInterval",
    "pub struct ConfidenceContext",
    "pub struct ActionCandidate",
    "pub struct SystemState",
    "pub struct RecommendedAction",
    "pub struct CopilotResponse",
    "pub struct DegradedWarning",
    "pub struct CopilotAuditEntry",
    "pub struct ActionRecommendationEngine",
    "pub fn compute_voi",
]

REQUIRED_EVENT_CODES = [
    "COPILOT_RECOMMENDATION_REQUESTED",
    "COPILOT_RECOMMENDATION_SERVED",
    "COPILOT_ROLLBACK_VALIDATED",
    "COPILOT_DEGRADED_WARNING",
    "COPILOT_STREAM_STARTED",
    "COPILOT_STREAM_UPDATED",
]

REQUIRED_LOSS_DIMS = [
    "availability_loss",
    "integrity_loss",
    "confidentiality_loss",
    "financial_loss",
    "reputation_loss",
]

REQUIRED_ENGINE_METHODS = [
    "pub fn recommend(",
    "pub fn audit_trail(",
    "pub fn total_served(",
    "pub fn top_k(",
]

REQUIRED_TESTS = [
    "test_compute_voi",
    "test_voi_ranking_order",
    "test_top_k_limiting",
    "test_empty_candidates",
    "test_degraded_mode_warning",
    "test_degraded_confidence_annotation",
    "test_normal_mode_no_degraded_flag",
    "test_rationale_includes_dominant_dimension",
    "test_rollback_command_included",
    "test_audit_trail_recorded",
    "test_expected_loss_vector_validation",
    "test_expected_loss_total",
    "test_confidence_interval_non_degenerate",
    "test_dominant_dimension",
    "test_tied_voi_stability",
    "test_adjusted_uncertainty_widened",
    "test_multiple_recommendations_served",
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
    has_module = "pub mod copilot_engine;" in content
    return {"pass": has_module, "registered": has_module}


def check_voi_formula() -> dict[str, Any]:
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found"}
    content = RUST_IMPL_PATH.read_text()
    has_voi_fn = "pub fn compute_voi" in content
    has_loss_diff = "loss_if_wait" in content and "loss_if_act" in content
    has_total = ".total()" in content
    return {
        "pass": all([has_voi_fn, has_loss_diff, has_total]),
        "voi_function": has_voi_fn,
        "loss_comparison": has_loss_diff,
        "total_aggregation": has_total,
    }


def check_degraded_integration() -> dict[str, Any]:
    if not RUST_IMPL_PATH.exists():
        return {"pass": False, "reason": "rust impl not found"}
    content = RUST_IMPL_PATH.read_text()
    has_degraded_field = "degraded_mode" in content
    has_degraded_warning = "DegradedWarning" in content
    has_stale_inputs = "stale_inputs" in content
    has_adjusted = "adjusted_uncertainty" in content
    return {
        "pass": all([has_degraded_field, has_degraded_warning, has_stale_inputs, has_adjusted]),
        "degraded_mode_field": has_degraded_field,
        "degraded_warning_struct": has_degraded_warning,
        "stale_inputs": has_stale_inputs,
        "adjusted_uncertainty": has_adjusted,
    }


def run_all_checks() -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = {
        "files": {
            "spec": check_file_exists(SPEC_PATH),
            "rust_impl": check_file_exists(RUST_IMPL_PATH),
            "mod_rs": check_file_exists(MOD_PATH),
        },
        "spec_invariants": check_content("spec", SPEC_PATH, REQUIRED_INVARIANTS),
        "rust_symbols": check_content("rust", RUST_IMPL_PATH, REQUIRED_RUST_SYMBOLS),
        "event_codes": check_content("rust", RUST_IMPL_PATH, REQUIRED_EVENT_CODES),
        "loss_dimensions": check_content("rust", RUST_IMPL_PATH, REQUIRED_LOSS_DIMS),
        "engine_methods": check_content("rust", RUST_IMPL_PATH, REQUIRED_ENGINE_METHODS),
        "tests": check_content("rust", RUST_IMPL_PATH, REQUIRED_TESTS),
        "mod_registration": check_mod_registration(),
        "voi_formula": check_voi_formula(),
        "degraded_integration": check_degraded_integration(),
    }

    check_results = [
        checks["spec_invariants"],
        checks["rust_symbols"],
        checks["event_codes"],
        checks["loss_dimensions"],
        checks["engine_methods"],
        checks["tests"],
        checks["mod_registration"],
        checks["voi_formula"],
        checks["degraded_integration"],
    ]

    all_pass = all(c.get("pass", False) for c in check_results)
    file_pass = all(f["exists"] for f in checks["files"].values())
    passed_count = sum(1 for c in check_results if c.get("pass", False)) + (1 if file_pass else 0)

    return {
        "bead_id": "bd-2yc",
        "section": "10.5",
        "title": "Operator Copilot Action Recommendation API",
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
    assert evidence["bead_id"] == "bd-2yc"
    assert "checks" in evidence
    assert "summary" in evidence
    expected = [
        "files", "spec_invariants", "rust_symbols", "event_codes",
        "loss_dimensions", "engine_methods", "tests",
        "mod_registration", "voi_formula", "degraded_integration",
    ]
    for cat in expected:
        assert cat in evidence["checks"], f"missing check: {cat}"
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify bd-2yc operator copilot API")
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
        print(f"bd-2yc verification: {status} ({s['passed']}/{s['total_checks']} checks passed)")
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
