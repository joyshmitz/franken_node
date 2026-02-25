#!/usr/bin/env python3
"""Verify bd-9is: Autonomous adversarial campaign runner.

Checks that the adversarial campaign runner infrastructure is correctly
implemented: Rust module present with required types, campaign corpus
fixture exists with >= 5 categories, mutation strategies defined,
event codes and invariants documented, spec contract present.

Usage:
    python scripts/check_adversarial_runner.py
    python scripts/check_adversarial_runner.py --json
    python scripts/check_adversarial_runner.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path
from typing import Any


CHECKS: list[dict[str, Any]] = []

CAMPAIGN_CATEGORIES = [
    ("CAMP-MEI", "MaliciousExtensionInjection"),
    ("CAMP-CEX", "CredentialExfiltration"),
    ("CAMP-PEV", "PolicyEvasion"),
    ("CAMP-DPA", "DelayedPayloadActivation"),
    ("CAMP-SCC", "SupplyChainCompromise"),
]

MUTATION_STRATEGIES = [
    ("MUT-PARAM", "ParameterVariation"),
    ("MUT-COMBO", "TechniqueCombination"),
    ("MUT-TIMING", "TimingVariation"),
    ("MUT-EVASION", "EvasionRefinement"),
]

REQUIRED_EVENT_CODES = [
    "ADV-RUN-001",
    "ADV-RUN-002",
    "ADV-RUN-003",
    "ADV-RUN-004",
    "ADV-RUN-005",
    "ADV-RUN-006",
    "ADV-RUN-ERR-001",
    "ADV-RUN-ERR-002",
]

REQUIRED_INVARIANTS = [
    "INV-ACR-CORPUS",
    "INV-ACR-SANDBOX",
    "INV-ACR-MUTATION",
    "INV-ACR-RESULTS",
    "INV-ACR-INTEGRATION",
    "INV-ACR-CONTINUOUS",
    "INV-ACR-PROVENANCE",
]


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    CHECKS.append(entry)
    return entry


def _safe_rel(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


def _read_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Checks: Rust implementation
# ---------------------------------------------------------------------------

def check_rust_module_exists() -> None:
    path = ROOT / "crates" / "franken-node" / "src" / "security" / "adversarial_runner.rs"
    exists = path.is_file()
    _check("rust_module_exists", exists, _safe_rel(path) if exists else f"missing: {_safe_rel(path)}")


def check_mod_registration() -> None:
    mod_rs = ROOT / "crates" / "franken-node" / "src" / "security" / "mod.rs"
    src = _read_text(mod_rs)
    registered = "pub mod adversarial_runner;" in src
    _check("mod_registration", registered, "adversarial_runner registered in security/mod.rs" if registered else "NOT registered")


def check_campaign_categories() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "security" / "adversarial_runner.rs")
    for cat_id, cat_enum in CAMPAIGN_CATEGORIES:
        id_found = f'"{cat_id}"' in src
        enum_found = cat_enum in src
        _check(f"category_{cat_id}", id_found and enum_found, f"{cat_id} ({cat_enum})" if id_found and enum_found else f"missing {cat_id}")


def check_mutation_strategies() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "security" / "adversarial_runner.rs")
    for mut_id, mut_enum in MUTATION_STRATEGIES:
        id_found = f'"{mut_id}"' in src
        enum_found = mut_enum in src
        _check(f"mutation_{mut_id}", id_found and enum_found, f"{mut_id} ({mut_enum})" if id_found and enum_found else f"missing {mut_id}")


def check_event_codes() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "security" / "adversarial_runner.rs")
    for code in REQUIRED_EVENT_CODES:
        found = f'"{code}"' in src
        _check(f"event_code_{code}", found, f"{code} defined" if found else f"{code} missing")


def check_invariant_constants() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "security" / "adversarial_runner.rs")
    for inv in REQUIRED_INVARIANTS:
        found = f'"{inv}"' in src
        _check(f"invariant_{inv}", found, f"{inv} defined" if found else f"{inv} missing")


def check_runner_struct() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "security" / "adversarial_runner.rs")
    found = "pub struct AdversarialRunner" in src
    _check("runner_struct", found, "AdversarialRunner defined" if found else "AdversarialRunner missing")


def check_evaluate_method() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "security" / "adversarial_runner.rs")
    found = "fn evaluate_results" in src
    _check("evaluate_method", found, "evaluate_results present" if found else "evaluate_results missing")


def check_corpus_builder() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "security" / "adversarial_runner.rs")
    found = "fn build_default_corpus" in src
    _check("corpus_builder", found, "build_default_corpus present" if found else "build_default_corpus missing")


def check_inline_tests() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "security" / "adversarial_runner.rs")
    test_count = len(re.findall(r"#\[test\]", src))
    passed = test_count >= 10
    _check("inline_tests", passed, f"{test_count} inline tests (need >= 10)")


def check_runner_modes() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "security" / "adversarial_runner.rs")
    continuous = '"continuous"' in src
    on_demand = '"on_demand"' in src
    _check("runner_modes", continuous and on_demand, "continuous + on_demand modes" if continuous and on_demand else "missing runner modes")


def check_sandbox_verification() -> None:
    src = _read_text(ROOT / "crates" / "franken-node" / "src" / "security" / "adversarial_runner.rs")
    found = "sandbox_verified" in src
    _check("sandbox_verification", found, "sandbox_verified field present" if found else "sandbox_verified missing")


# ---------------------------------------------------------------------------
# Checks: Campaign corpus fixture
# ---------------------------------------------------------------------------

def check_corpus_fixture_exists() -> None:
    path = ROOT / "fixtures" / "campaigns" / "initial_corpus.json"
    exists = path.is_file()
    _check("corpus_fixture_exists", exists, _safe_rel(path) if exists else f"missing: {_safe_rel(path)}")


def check_corpus_fixture_valid_json() -> None:
    path = ROOT / "fixtures" / "campaigns" / "initial_corpus.json"
    if not path.is_file():
        _check("corpus_fixture_valid_json", False, "fixture file missing")
        return
    try:
        data = json.loads(path.read_text())
        _check("corpus_fixture_valid_json", isinstance(data, dict), "valid JSON object")
    except json.JSONDecodeError as e:
        _check("corpus_fixture_valid_json", False, f"invalid JSON: {e}")


def check_corpus_fixture_categories() -> None:
    path = ROOT / "fixtures" / "campaigns" / "initial_corpus.json"
    if not path.is_file():
        _check("corpus_fixture_categories", False, "fixture missing")
        return
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        _check("corpus_fixture_categories", False, "invalid JSON")
        return

    campaigns = data.get("campaigns", [])
    categories = {c.get("category", "") for c in campaigns if isinstance(c, dict)}
    passed = len(categories) >= 5
    _check("corpus_fixture_categories", passed, f"{len(categories)} categories in fixture (need >= 5)")


def check_corpus_fixture_campaign_count() -> None:
    path = ROOT / "fixtures" / "campaigns" / "initial_corpus.json"
    if not path.is_file():
        _check("corpus_fixture_campaign_count", False, "fixture missing")
        return
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        _check("corpus_fixture_campaign_count", False, "invalid JSON")
        return

    campaigns = data.get("campaigns", [])
    passed = len(campaigns) >= 5
    _check("corpus_fixture_campaign_count", passed, f"{len(campaigns)} campaigns (need >= 5)")


# ---------------------------------------------------------------------------
# Checks: Spec contract
# ---------------------------------------------------------------------------

def check_spec_contract() -> None:
    path = ROOT / "docs" / "specs" / "section_10_9" / "bd-9is_contract.md"
    exists = path.is_file()
    _check("spec_contract", exists, _safe_rel(path) if exists else f"missing: {_safe_rel(path)}")


def check_spec_categories() -> None:
    src = _read_text(ROOT / "docs" / "specs" / "section_10_9" / "bd-9is_contract.md")
    for cat_id, _ in CAMPAIGN_CATEGORIES:
        found = cat_id in src
        _check(f"spec_category_{cat_id}", found, f"{cat_id} in spec" if found else f"{cat_id} missing from spec")


def check_spec_mutation_strategies() -> None:
    src = _read_text(ROOT / "docs" / "specs" / "section_10_9" / "bd-9is_contract.md")
    for mut_id, _ in MUTATION_STRATEGIES:
        found = mut_id in src
        _check(f"spec_mutation_{mut_id}", found, f"{mut_id} in spec" if found else f"{mut_id} missing from spec")


def check_spec_event_codes() -> None:
    src = _read_text(ROOT / "docs" / "specs" / "section_10_9" / "bd-9is_contract.md")
    for code in REQUIRED_EVENT_CODES:
        found = code in src
        _check(f"spec_event_{code}", found, f"{code} in spec" if found else f"{code} missing from spec")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all_checks() -> list[dict[str, Any]]:
    CHECKS.clear()

    # Rust implementation
    check_rust_module_exists()
    check_mod_registration()
    check_campaign_categories()
    check_mutation_strategies()
    check_event_codes()
    check_invariant_constants()
    check_runner_struct()
    check_evaluate_method()
    check_corpus_builder()
    check_inline_tests()
    check_runner_modes()
    check_sandbox_verification()

    # Corpus fixture
    check_corpus_fixture_exists()
    check_corpus_fixture_valid_json()
    check_corpus_fixture_categories()
    check_corpus_fixture_campaign_count()

    # Spec contract
    check_spec_contract()
    check_spec_categories()
    check_spec_mutation_strategies()
    check_spec_event_codes()

    return CHECKS


def run_all() -> dict[str, Any]:
    checks = run_all_checks()
    total = len(checks)
    passed = sum(1 for c in checks if c["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-9is",
        "title": "Autonomous adversarial campaign runner with continuous updates",
        "section": "10.9",
        "gate": False,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "overall_pass": failed == 0,
        "total": total,
        "passed": passed,
        "failed": failed,
        "campaign_categories": [cat_id for cat_id, _ in CAMPAIGN_CATEGORIES],
        "mutation_strategies": [mut_id for mut_id, _ in MUTATION_STRATEGIES],
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
            print(f"SELF-TEST FAIL: malformed entry: {entry}", file=sys.stderr)
            return False

    print(f"SELF-TEST OK: {len(checks)} checks returned", file=sys.stderr)
    return True


def main() -> None:
    logger = configure_test_logging("check_adversarial_runner")
    parser = argparse.ArgumentParser(description="bd-9is: adversarial campaign runner verification")
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
            f"\n  Adversarial Runner: {'PASS' if output['overall_pass'] else 'FAIL'} "
            f"({output['passed']}/{output['total']})\n"
        )
        for entry in output["checks"]:
            mark = "+" if entry["pass"] else "x"
            print(f"  [{mark}] {entry['check']}: {entry['detail']}")

    sys.exit(0 if output["overall_pass"] else 1)


if __name__ == "__main__":
    main()
