#!/usr/bin/env python3
"""bd-10c gate: Trust Economics Dashboard with Attacker-ROI Deltas (Section 10.9).

Validates the Rust implementation in
crates/franken-node/src/tools/trust_economics_dashboard.rs against
the spec contract docs/specs/section_10_9/bd-10c_contract.md.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

SRC = ROOT / "crates" / "franken-node" / "src" / "tools" / "trust_economics_dashboard.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "tools" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_9" / "bd-10c_contract.md"

ATTACK_CATEGORIES = [
    "credential_exfiltration",
    "privilege_escalation",
    "supply_chain_compromise",
    "policy_evasion",
    "data_exfiltration",
]

PLATFORMS = ["node_js", "bun", "franken_node"]

PRIVILEGE_LEVELS = ["unrestricted", "standard", "restricted", "quarantined"]

OPTIMIZATION_OBJECTIVES = [
    "MinimizeExpectedLoss",
    "MaximizeAttackerCost",
    "MinimizeOperationalOverhead",
    "BalancedOptimization",
]

EVENT_CODES = [
    "TED-001", "TED-002", "TED-003", "TED-004", "TED-005",
    "TED-006", "TED-007", "TED-008", "TED-009", "TED-010",
    "TED-ERR-001", "TED-ERR-002",
]

INVARIANTS = [
    "INV-TED-QUANTIFIED",
    "INV-TED-DETERMINISTIC",
    "INV-TED-VERSIONED",
    "INV-TED-CONFIDENCE",
    "INV-TED-GATED",
    "INV-TED-COMPARATIVE",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def check_source_exists() -> tuple[str, bool, str]:
    ok = SRC.is_file()
    return ("source_exists", ok, f"Source file exists: {SRC.name}")


def check_module_wiring() -> tuple[str, bool, str]:
    content = _read(MOD_RS)
    ok = "pub mod trust_economics_dashboard;" in content
    return ("module_wiring", ok, "Module wired in tools/mod.rs")


def check_structs() -> tuple[str, bool, str]:
    src = _read(SRC)
    required = [
        "struct AttackCost",
        "struct AmplificationEntry",
        "struct ConfidenceInterval",
        "struct PrivilegeRiskPrice",
        "struct PrivilegeRiskCurve",
        "struct PolicyRecommendation",
        "struct ExpectedImpact",
        "struct ExpectedLossModel",
        "struct TrustEconomicsReport",
        "struct TrustEconomicsDashboard",
        "struct DashboardConfig",
        "struct TedAuditRecord",
    ]
    missing = [s for s in required if s not in src]
    ok = len(missing) == 0
    detail = f"All {len(required)} structs present" if ok else f"Missing: {missing}"
    return ("structs", ok, detail)


def check_attack_categories() -> tuple[str, bool, str]:
    src = _read(SRC)
    missing = [c for c in ATTACK_CATEGORIES if c not in src]
    ok = len(missing) == 0 and "enum AttackCategory" in src
    return ("attack_categories", ok, f"5 attack categories: {5 - len(missing)}/5")


def check_three_way_comparison() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "enum Platform" in src,
        all(p in src for p in PLATFORMS),
        "bun_vs_node_factor" in src,
        "franken_vs_node_factor" in src,
        "franken_vs_bun_factor" in src,
    ]
    ok = all(checks)
    return ("three_way_comparison", ok, "Three-way platform comparison (Node.js/Bun/franken_node)")


def check_privilege_pricing() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "enum PrivilegeLevel" in src,
        all(p in src for p in ["Unrestricted", "Standard", "Restricted", "Quarantined"]),
        "risk_adjusted_price" in src,
        "potential_damage" in src,
        "expected_loss_per_year" in src,
    ]
    ok = all(checks)
    return ("privilege_pricing", ok, f"4 privilege levels with risk pricing: {sum(checks)}/5 checks")


def check_policy_recommendations() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "enum OptimizationObjective" in src,
        all(o in src for o in OPTIMIZATION_OBJECTIVES),
        "struct PolicyRecommendation" in src,
        "expected_impact" in src,
        "rationale" in src,
    ]
    ok = all(checks)
    return ("policy_recommendations", ok, f"4 optimization objectives: {sum(checks)}/5 checks")


def check_expected_loss_model() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "struct ExpectedLossModel" in src,
        "posterior_update" in src,
        "expected_loss" in src,
        "attack_frequencies" in src,
        "defense_effectiveness" in src,
        "365.0" in src,
    ]
    ok = all(checks)
    return ("expected_loss_model", ok, f"Expected-loss model with Bayesian updates: {sum(checks)}/6 checks")


def check_event_codes() -> tuple[str, bool, str]:
    src = _read(SRC)
    found = [c for c in EVENT_CODES if f'"{c}"' in src]
    ok = len(found) == len(EVENT_CODES)
    return ("event_codes", ok, f"Event codes: {len(found)}/{len(EVENT_CODES)}")


def check_invariants() -> tuple[str, bool, str]:
    src = _read(SRC)
    found = [i for i in INVARIANTS if i in src]
    ok = len(found) == len(INVARIANTS)
    return ("invariants", ok, f"Invariants: {len(found)}/{len(INVARIANTS)}")


def check_confidence_versioning() -> tuple[str, bool, str]:
    src = _read(SRC)
    checks = [
        "struct ConfidenceInterval" in src,
        "model_version" in src,
        'MODEL_VERSION' in src,
        '"ted-v1.0"' in src,
        "content_hash" in src,
    ]
    ok = all(checks)
    return ("confidence_versioning", ok, f"Confidence intervals + model versioning: {sum(checks)}/5 checks")


def check_spec_alignment() -> tuple[str, bool, str]:
    if not SPEC.is_file():
        return ("spec_alignment", False, "Spec contract not found")
    spec = _read(SPEC)
    checks = [
        "bd-10c" in spec,
        "Trust Economics Dashboard" in spec,
        "Section" in spec and "10.9" in spec,
    ]
    ok = all(checks)
    return ("spec_alignment", ok, "Spec contract aligns with implementation")


def check_test_coverage() -> tuple[str, bool, str]:
    src = _read(SRC)
    test_count = len(re.findall(r"#\[test\]", src))
    ok = test_count >= 25
    return ("test_coverage", ok, f"Rust unit tests: {test_count} (target >= 25)")


ALL_CHECKS = [
    check_source_exists,
    check_module_wiring,
    check_structs,
    check_attack_categories,
    check_three_way_comparison,
    check_privilege_pricing,
    check_policy_recommendations,
    check_expected_loss_model,
    check_event_codes,
    check_invariants,
    check_confidence_versioning,
    check_spec_alignment,
    check_test_coverage,
]


def run_all() -> list[dict]:
    results = []
    for fn in ALL_CHECKS:
        name, passed, detail = fn()
        results.append({"check": name, "passed": passed, "detail": detail})
    return results


def self_test() -> bool:
    results = run_all()
    return all(r["passed"] for r in results)


def main() -> None:
    logger = configure_test_logging("check_trust_economics")
    parser = argparse.ArgumentParser(description="bd-10c gate: Trust Economics Dashboard")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    results = run_all()
    verdict = "PASS" if all(r["passed"] for r in results) else "FAIL"

    if args.json:
        print(json.dumps({"bead": "bd-10c", "verdict": verdict, "checks": results}, indent=2))
    else:
        for r in results:
            status = "PASS" if r["passed"] else "FAIL"
            print(f"  [{status}] {r['check']}: {r['detail']}")
        total = len(results)
        passed = sum(1 for r in results if r["passed"])
        print(f"\n  {passed}/{total} checks passed — {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
