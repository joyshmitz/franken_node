#!/usr/bin/env python3
"""Verification script for bd-3lh: cold-start and p99 latency gates.

Usage:
    python scripts/check_latency_gates.py                # human-readable
    python scripts/check_latency_gates.py --json          # machine-readable
    python scripts/check_latency_gates.py --self-test
    python scripts/check_latency_gates.py --profile ci_dev  # specific profile
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

SPEC_PATH = ROOT / "docs" / "specs" / "section_10_6" / "bd-3lh_contract.md"
BUDGETS_PATH = ROOT / "perf" / "budgets.toml"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RESULTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    RESULTS.append(entry)
    return entry


def _safe_relative(path: Path) -> str:
    if str(path).startswith(str(ROOT)):
        return str(path.relative_to(ROOT))
    return str(path)


# ---------------------------------------------------------------------------
# TOML parsing (stdlib tomllib for Python 3.11+)
# ---------------------------------------------------------------------------

def _load_toml(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            # Fallback: parse just enough for verification
            return _fallback_parse_toml(path)
    with open(path, "rb") as f:
        return tomllib.load(f)


def _fallback_parse_toml(path: Path) -> dict[str, Any]:
    """Minimal TOML parser for verification (handles flat tables and values)."""
    text = path.read_text()
    result: dict[str, Any] = {}
    current_section: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            current_section = section.split(".")
            # Create nested dict
            d = result
            for key in current_section:
                if key not in d:
                    d[key] = {}
                d = d[key]
        elif "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"')
            try:
                value = int(value)
            except (ValueError, TypeError):
                try:
                    value = float(value)
                except (ValueError, TypeError):
                    pass
            d = result
            for k in current_section:
                d = d.setdefault(k, {})
            d[key] = value
    return result


# ---------------------------------------------------------------------------
# Budget resolution
# ---------------------------------------------------------------------------

WORKFLOWS = [
    "migration_scan",
    "compatibility_check",
    "policy_evaluation",
    "trust_card_lookup",
    "incident_replay",
]

PROFILES = ["dev_local", "ci_dev", "enterprise"]


def get_budget(config: dict, profile: str, workflow: str) -> dict[str, int]:
    """Resolve cold_start_ms and p99_latency_ms for a workflow+profile."""
    defaults = config.get("profiles", {}).get(profile, {})
    overrides = (
        config.get("workflows", {})
        .get(workflow, {})
        .get("overrides", {})
        .get(profile, {})
    )
    return {
        "cold_start_ms": overrides.get("cold_start_ms", defaults.get("cold_start_ms", 0)),
        "p99_latency_ms": overrides.get("p99_latency_ms", defaults.get("p99_latency_ms", 0)),
    }


# ---------------------------------------------------------------------------
# Statistics helpers
# ---------------------------------------------------------------------------


def percentile(values: list[float], pct: float) -> float:
    """Compute the given percentile from a sorted list."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    d0 = sorted_vals[int(f)] * (c - k)
    d1 = sorted_vals[int(c)] * (k - f)
    return d0 + d1


# ---------------------------------------------------------------------------
# Spec checks
# ---------------------------------------------------------------------------


def check_spec_exists() -> dict[str, Any]:
    exists = SPEC_PATH.is_file()
    return _check(
        "spec_exists",
        exists,
        f"exists: {_safe_relative(SPEC_PATH)}" if exists else f"missing: {_safe_relative(SPEC_PATH)}",
    )


def check_budgets_exists() -> dict[str, Any]:
    exists = BUDGETS_PATH.is_file()
    return _check(
        "budgets_exists",
        exists,
        f"exists: {_safe_relative(BUDGETS_PATH)}" if exists else f"missing: {_safe_relative(BUDGETS_PATH)}",
    )


# ---------------------------------------------------------------------------
# Spec keyword checks
# ---------------------------------------------------------------------------


def check_spec_keyword_cold_start() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_keyword_cold_start", False, "spec missing")
    text = SPEC_PATH.read_text().lower()
    return _check("spec_keyword_cold_start", "cold-start" in text or "cold_start" in text)


def check_spec_keyword_p99() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_keyword_p99", False, "spec missing")
    text = SPEC_PATH.read_text()
    return _check("spec_keyword_p99", "p99" in text or "P99" in text)


def check_spec_keyword_flamegraph() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_keyword_flamegraph", False, "spec missing")
    text = SPEC_PATH.read_text().lower()
    return _check("spec_keyword_flamegraph", "flamegraph" in text)


def check_spec_keyword_profiles() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_keyword_profiles", False, "spec missing")
    text = SPEC_PATH.read_text()
    found = all(p in text for p in ["dev_local", "ci_dev", "enterprise"])
    return _check("spec_keyword_profiles", found, "all 3 profiles present" if found else "profiles missing")


def check_spec_keyword_early_warning() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_keyword_early_warning", False, "spec missing")
    text = SPEC_PATH.read_text()
    return _check("spec_keyword_early_warning", "80%" in text)


def check_spec_event_codes() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_event_codes", False, "spec missing")
    text = SPEC_PATH.read_text()
    codes = ["LG-001", "LG-002", "LG-003", "LG-004", "LG-005", "LG-006", "LG-007", "LG-008"]
    missing = [c for c in codes if c not in text]
    return _check("spec_event_codes", not missing, "all 8 present" if not missing else f"missing: {', '.join(missing)}")


def check_spec_invariants() -> dict[str, Any]:
    if not SPEC_PATH.is_file():
        return _check("spec_invariants", False, "spec missing")
    text = SPEC_PATH.read_text()
    invariants = ["INV-LG-MIN-SAMPLES", "INV-LG-PROFILE-SPECIFIC", "INV-LG-VERSIONED-BUDGETS",
                  "INV-LG-EARLY-WARNING", "INV-LG-STRUCTURED-OUTPUT"]
    missing = [i for i in invariants if i not in text]
    return _check("spec_invariants", not missing, "all 5 present" if not missing else f"missing: {', '.join(missing)}")


# ---------------------------------------------------------------------------
# Budget config checks
# ---------------------------------------------------------------------------


def check_budgets_has_profiles() -> dict[str, Any]:
    config = _load_toml(BUDGETS_PATH)
    if config is None:
        return _check("budgets_has_profiles", False, "budgets.toml missing")
    profiles = config.get("profiles", {})
    missing = [p for p in PROFILES if p not in profiles]
    return _check(
        "budgets_has_profiles",
        not missing,
        f"all 3 profiles present" if not missing else f"missing: {', '.join(missing)}",
    )


def check_budgets_has_workflows() -> dict[str, Any]:
    config = _load_toml(BUDGETS_PATH)
    if config is None:
        return _check("budgets_has_workflows", False, "budgets.toml missing")
    workflows = config.get("workflows", {})
    missing = [w for w in WORKFLOWS if w not in workflows]
    return _check(
        "budgets_has_workflows",
        not missing,
        f"all 5 workflows present" if not missing else f"missing: {', '.join(missing)}",
    )


def check_budgets_version() -> dict[str, Any]:
    config = _load_toml(BUDGETS_PATH)
    if config is None:
        return _check("budgets_version", False, "budgets.toml missing")
    meta = config.get("meta", {})
    version = meta.get("version", "")
    return _check("budgets_version", bool(version), f"version: {version}" if version else "no version")


def check_budgets_min_iterations() -> dict[str, Any]:
    config = _load_toml(BUDGETS_PATH)
    if config is None:
        return _check("budgets_min_iterations", False, "budgets.toml missing")
    meta = config.get("meta", {})
    min_iter = meta.get("min_iterations", 0)
    passed = min_iter >= 30
    return _check("budgets_min_iterations", passed, f"min_iterations: {min_iter} (>= 30 required)")


def check_budget_resolution() -> dict[str, Any]:
    """Verify budget resolution with overrides works correctly."""
    config = _load_toml(BUDGETS_PATH)
    if config is None:
        return _check("budget_resolution", False, "budgets.toml missing")

    # migration_scan should have overrides for dev_local
    budget = get_budget(config, "dev_local", "migration_scan")
    has_override = budget["cold_start_ms"] != config.get("profiles", {}).get("dev_local", {}).get("cold_start_ms", 0)
    return _check(
        "budget_resolution",
        has_override,
        f"migration_scan dev_local override: cold_start={budget['cold_start_ms']}ms" if has_override
        else "no override detected for migration_scan",
    )


def check_budget_values_positive() -> dict[str, Any]:
    config = _load_toml(BUDGETS_PATH)
    if config is None:
        return _check("budget_values_positive", False, "budgets.toml missing")

    all_positive = True
    for profile in PROFILES:
        for workflow in WORKFLOWS:
            b = get_budget(config, profile, workflow)
            if b["cold_start_ms"] <= 0 or b["p99_latency_ms"] <= 0:
                all_positive = False
                break
    return _check("budget_values_positive", all_positive, "all budgets > 0" if all_positive else "zero/negative budget found")


def check_budget_enterprise_stricter() -> dict[str, Any]:
    """Enterprise budgets must be stricter than dev_local."""
    config = _load_toml(BUDGETS_PATH)
    if config is None:
        return _check("budget_enterprise_stricter", False, "budgets.toml missing")

    enterprise = config.get("profiles", {}).get("enterprise", {})
    dev_local = config.get("profiles", {}).get("dev_local", {})
    stricter = (
        enterprise.get("cold_start_ms", 999) < dev_local.get("cold_start_ms", 0) and
        enterprise.get("p99_latency_ms", 999) < dev_local.get("p99_latency_ms", 0)
    )
    return _check("budget_enterprise_stricter", stricter, "enterprise < dev_local" if stricter else "NOT stricter")


# ---------------------------------------------------------------------------
# Statistics checks
# ---------------------------------------------------------------------------


def check_percentile_computation() -> dict[str, Any]:
    """Verify p99 computation with known data."""
    data = list(range(1, 101))  # 1 to 100
    p99 = percentile(data, 99)
    passed = abs(p99 - 99.01) < 0.1
    return _check("percentile_computation", passed, f"p99 of [1..100] = {p99:.2f} (expected ~99.01)")


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------


def run_all_checks() -> list[dict[str, Any]]:
    RESULTS.clear()
    check_spec_exists()
    check_budgets_exists()
    check_spec_keyword_cold_start()
    check_spec_keyword_p99()
    check_spec_keyword_flamegraph()
    check_spec_keyword_profiles()
    check_spec_keyword_early_warning()
    check_spec_event_codes()
    check_spec_invariants()
    check_budgets_has_profiles()
    check_budgets_has_workflows()
    check_budgets_version()
    check_budgets_min_iterations()
    check_budget_resolution()
    check_budget_values_positive()
    check_budget_enterprise_stricter()
    check_percentile_computation()
    return RESULTS


def self_test() -> bool:
    results = run_all_checks()
    if not results:
        print("SELF-TEST FAIL: no checks returned", file=sys.stderr)
        return False
    for r in results:
        if not isinstance(r, dict):
            print(f"SELF-TEST FAIL: bad result type: {type(r)}", file=sys.stderr)
            return False
        for key in ("check", "pass", "detail"):
            if key not in r:
                print(f"SELF-TEST FAIL: missing key '{key}' in {r}", file=sys.stderr)
                return False
    print(f"SELF-TEST OK: {len(results)} checks returned", file=sys.stderr)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify bd-3lh latency gates")
    parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    parser.add_argument("--profile", default="ci_dev", help="Deployment profile (default: ci_dev)")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)

    results = run_all_checks()
    total = len(results)
    passed = sum(1 for r in results if r["pass"])
    failed = total - passed
    overall = failed == 0

    if args.json:
        output = {
            "bead_id": "bd-3lh",
            "title": "Cold-start and p99 latency gates for core workflows",
            "section": "10.6",
            "verdict": "PASS" if overall else "FAIL",
            "overall_pass": overall,
            "total": total,
            "passed": passed,
            "failed": failed,
            "profile": args.profile,
            "checks": results,
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"\n  bd-3lh verification: {'PASS' if overall else 'FAIL'} ({passed}/{total})\n")
        for r in results:
            mark = "+" if r["pass"] else "x"
            print(f"  [{mark}] {r['check']}: {r['detail']}")

    sys.exit(0 if overall else 1)


if __name__ == "__main__":
    main()
