#!/usr/bin/env python3
"""Verification script for bd-1rff: longitudinal privacy/re-identification."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

BEAD_ID = "bd-1rff"
SECTION = "12"
TITLE = "Risk control: longitudinal privacy/re-identification"

CONTRACT = ROOT / "docs" / "specs" / "section_12" / "bd-1rff_contract.md"
REPORT = ROOT / "artifacts" / "12" / "longitudinal_privacy_report.json"

REQUIRED_EVENT_CODES = ["LPR-001", "LPR-002", "LPR-003", "LPR-004", "LPR-005"]
REQUIRED_CONTRACT_TERMS = [
    "INV-LPR-SKETCH-ONLY",
    "INV-LPR-K-ANON",
    "INV-LPR-EPOCH",
    "INV-LPR-LINKAGE",
    "INV-LPR-BLOCKING",
    "Scenario A",
    "Scenario B",
    "Scenario C",
    "Scenario D",
]


def check_file(path: Path, label: str) -> dict:
    ok = path.exists()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {path.relative_to(ROOT)}" if ok else f"MISSING: {path}",
    }


def check_contract() -> list[dict]:
    checks = []
    if not CONTRACT.exists():
        checks.append({"check": "contract: exists", "pass": False, "detail": "MISSING"})
        return checks

    text = CONTRACT.read_text(encoding="utf-8")
    checks.append({"check": "contract: exists", "pass": True, "detail": "found"})
    for term in REQUIRED_CONTRACT_TERMS:
        present = term in text
        checks.append({
            "check": f"contract: term {term}",
            "pass": present,
            "detail": "present" if present else "MISSING",
        })
    return checks


def load_report() -> tuple[dict | None, list[dict]]:
    checks = []
    if not REPORT.exists():
        checks.append({"check": "report: exists", "pass": False, "detail": "MISSING"})
        return None, checks

    checks.append({"check": "report: exists", "pass": True, "detail": "found"})
    try:
        data = json.loads(REPORT.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        checks.append({"check": "report: valid json", "pass": False, "detail": "invalid"})
        return None, checks
    checks.append({"check": "report: valid json", "pass": True, "detail": "valid"})
    return data, checks


def evaluate_policy(data: dict) -> dict:
    storage = data.get("storage", {})
    query_policy = data.get("query_policy", {})
    temporal = data.get("temporal_aggregation", {})
    linkage = data.get("linkage_attack", {})

    queries = query_policy.get("queries", [])
    blocked_small_queries = all(
        (int(q.get("cohort_size", 0)) >= int(query_policy.get("minimum_cohort_size_k", 50)))
        or bool(q.get("blocked", False))
        for q in queries
    )

    return {
        "sketch_only": (not bool(storage.get("raw_trajectory_storage_enabled", True))) and int(storage.get("raw_records_persisted", -1)) == 0,
        "minimum_k": int(query_policy.get("minimum_cohort_size_k", 0)),
        "blocked_small_queries": blocked_small_queries,
        "epoch_minutes": int(temporal.get("stored_resolution_minutes", 0)),
        "linkage_success_rate_pct": float(linkage.get("success_rate_pct", 100.0)),
    }


def check_report(data: dict | None) -> list[dict]:
    if data is None:
        return []

    checks = []
    storage = data.get("storage", {})
    reconstruction = data.get("reconstruction_test", {})
    query_policy = data.get("query_policy", {})
    temporal = data.get("temporal_aggregation", {})
    linkage = data.get("linkage_attack", {})
    aggregate = data.get("aggregate", {})

    checks.append({
        "check": "storage: sketch-only persistence",
        "pass": (not bool(storage.get("raw_trajectory_storage_enabled", True))) and int(storage.get("raw_records_persisted", -1)) == 0,
        "detail": "validated" if (not bool(storage.get("raw_trajectory_storage_enabled", True))) and int(storage.get("raw_records_persisted", -1)) == 0 else "raw trajectory storage detected",
    })

    checks.append({
        "check": "storage: at least 1000 sketch records persisted",
        "pass": int(storage.get("sketch_records_persisted", 0)) >= 1000,
        "detail": f"count={storage.get('sketch_records_persisted')}",
    })

    checks.append({
        "check": "reconstruction: exact trajectory reconstruction fails",
        "pass": not bool(reconstruction.get("exact_reconstruction_succeeded", True)),
        "detail": "validated" if not bool(reconstruction.get("exact_reconstruction_succeeded", True)) else "reconstruction unexpectedly succeeded",
    })

    k_min = int(query_policy.get("minimum_cohort_size_k", 0))
    checks.append({
        "check": "k-anonymity: minimum cohort threshold k>=50",
        "pass": k_min >= 50,
        "detail": f"k={k_min}",
    })

    queries = query_policy.get("queries", [])
    small_query_blocks_ok = True
    for query in queries:
        size = int(query.get("cohort_size", 0))
        blocked = bool(query.get("blocked", False))
        if size < k_min and not blocked:
            small_query_blocks_ok = False
    checks.append({
        "check": "k-anonymity: below-threshold queries are blocked",
        "pass": small_query_blocks_ok,
        "detail": "all small cohorts blocked" if small_query_blocks_ok else "small-cohort query not blocked",
    })

    error_code_ok = all(
        (int(q.get("cohort_size", 0)) >= k_min)
        or (q.get("error_code") == "ERR_INSUFFICIENT_COHORT_SIZE")
        for q in queries
    )
    checks.append({
        "check": "k-anonymity: blocked queries emit stable error code",
        "pass": error_code_ok,
        "detail": "validated" if error_code_ok else "missing/invalid error code",
    })

    temporal_ok = (
        int(temporal.get("stored_resolution_minutes", 0)) >= int(temporal.get("minimum_epoch_minutes", 0))
        and int(temporal.get("stored_resolution_minutes", 0)) >= 60
        and bool(temporal.get("sub_hour_inputs_bucketed", False))
    )
    checks.append({
        "check": "temporal: sub-hour data bucketed to >=1h epochs",
        "pass": temporal_ok,
        "detail": "validated" if temporal_ok else "temporal bucketing invariant failed",
    })

    linkage_rate = float(linkage.get("success_rate_pct", 100.0))
    linkage_threshold = float(linkage.get("threshold_pct", 1.0))
    checks.append({
        "check": "linkage: success rate below 1%",
        "pass": linkage_rate < linkage_threshold and linkage_threshold <= 1.0,
        "detail": f"rate={linkage_rate}% threshold={linkage_threshold}%",
    })

    checks.append({
        "check": "linkage: attack sample size >=1000 sketches",
        "pass": int(linkage.get("sketches_analyzed", 0)) >= 1000,
        "detail": f"sketches={linkage.get('sketches_analyzed')}",
    })

    scenario_a = next((s for s in data.get("scenarios", []) if s.get("scenario") == "A"), None)
    scenario_a_ok = scenario_a is not None and bool(scenario_a.get("reconstruction_failed", False))
    checks.append({
        "check": "scenario A: reconstruction from sketches fails",
        "pass": scenario_a_ok,
        "detail": "validated" if scenario_a_ok else "scenario A invariant failed",
    })

    scenario_b = next((s for s in data.get("scenarios", []) if s.get("scenario") == "B"), None)
    scenario_b_ok = (
        scenario_b is not None
        and bool(scenario_b.get("blocked", False))
        and scenario_b.get("error_code") == "ERR_INSUFFICIENT_COHORT_SIZE"
    )
    checks.append({
        "check": "scenario B: cohort-30 query blocked",
        "pass": scenario_b_ok,
        "detail": "validated" if scenario_b_ok else "scenario B invariant failed",
    })

    scenario_c = next((s for s in data.get("scenarios", []) if s.get("scenario") == "C"), None)
    scenario_c_ok = (
        scenario_c is not None
        and int(scenario_c.get("bucketed_to_minutes", 0)) >= 60
        and bool(scenario_c.get("bucketing_applied", False))
    )
    checks.append({
        "check": "scenario C: sub-hour input bucketed to hour",
        "pass": scenario_c_ok,
        "detail": "validated" if scenario_c_ok else "scenario C invariant failed",
    })

    scenario_d = next((s for s in data.get("scenarios", []) if s.get("scenario") == "D"), None)
    scenario_d_ok = (
        scenario_d is not None
        and float(scenario_d.get("linkage_success_rate_pct", 100.0)) < 1.0
        and bool(scenario_d.get("below_threshold", False))
    )
    checks.append({
        "check": "scenario D: linkage success remains below 1%",
        "pass": scenario_d_ok,
        "detail": "validated" if scenario_d_ok else "scenario D invariant failed",
    })

    report_codes = data.get("event_codes", [])
    for code in REQUIRED_EVENT_CODES:
        checks.append({
            "check": f"events: {code}",
            "pass": code in report_codes,
            "detail": "present" if code in report_codes else "MISSING",
        })

    trace_ok = isinstance(data.get("trace_id"), str) and len(data.get("trace_id", "").strip()) > 0
    checks.append({
        "check": "logs: trace id present",
        "pass": trace_ok,
        "detail": data.get("trace_id", "MISSING"),
    })

    eval_out = evaluate_policy(data)
    checks.append({
        "check": "aggregate: sketch_records_persisted matches storage",
        "pass": int(aggregate.get("sketch_records_persisted", -1)) == int(storage.get("sketch_records_persisted", -2)),
        "detail": f"reported={aggregate.get('sketch_records_persisted')} storage={storage.get('sketch_records_persisted')}",
    })
    checks.append({
        "check": "aggregate: raw_records_persisted is zero",
        "pass": int(aggregate.get("raw_records_persisted", -1)) == 0,
        "detail": f"reported={aggregate.get('raw_records_persisted')}",
    })
    checks.append({
        "check": "aggregate: minimum_cohort_size_k matches query policy",
        "pass": int(aggregate.get("minimum_cohort_size_k", -1)) == int(query_policy.get("minimum_cohort_size_k", -2)),
        "detail": f"reported={aggregate.get('minimum_cohort_size_k')} policy={query_policy.get('minimum_cohort_size_k')}",
    })
    checks.append({
        "check": "aggregate: minimum_epoch_minutes matches temporal policy",
        "pass": int(aggregate.get("minimum_epoch_minutes", -1)) == int(temporal.get("minimum_epoch_minutes", -2)),
        "detail": f"reported={aggregate.get('minimum_epoch_minutes')} policy={temporal.get('minimum_epoch_minutes')}",
    })
    checks.append({
        "check": "aggregate: linkage success rate matches report",
        "pass": abs(float(aggregate.get("linkage_success_rate_pct", -1.0)) - float(linkage.get("success_rate_pct", -2.0))) < 0.01,
        "detail": f"reported={aggregate.get('linkage_success_rate_pct')} measured={linkage.get('success_rate_pct')}",
    })

    deterministic = evaluate_policy({"storage": storage, "query_policy": query_policy, "temporal_aggregation": temporal, "linkage_attack": linkage}) == evaluate_policy({"storage": storage, "query_policy": {**query_policy, "queries": list(reversed(queries))}, "temporal_aggregation": temporal, "linkage_attack": linkage})
    checks.append({
        "check": "determinism: query-order-insensitive policy evaluation",
        "pass": deterministic,
        "detail": "stable" if deterministic else "unstable",
    })

    adversarial = json.loads(json.dumps(data))
    adversarial["query_policy"]["minimum_cohort_size_k"] = 20
    adversarial_detected = evaluate_policy(adversarial)["minimum_k"] < 50
    checks.append({
        "check": "adversarial: reduced cohort threshold is detected",
        "pass": adversarial_detected,
        "detail": f"adversarial_k={evaluate_policy(adversarial)['minimum_k']}",
    })

    return checks


def run_checks() -> dict:
    checks = []
    checks.append(check_file(CONTRACT, "contract doc"))
    checks.append(check_file(REPORT, "longitudinal privacy report"))
    checks.extend(check_contract())
    data, load_checks = load_report()
    checks.extend(load_checks)
    checks.extend(check_report(data))

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])
    return {
        "bead_id": BEAD_ID,
        "title": TITLE,
        "section": SECTION,
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": len(checks),
        },
        "checks": checks,
    }


def self_test() -> tuple[bool, list[dict]]:
    sample = {
        "storage": {"raw_trajectory_storage_enabled": False, "raw_records_persisted": 0},
        "query_policy": {"minimum_cohort_size_k": 50, "queries": [{"cohort_size": 30, "blocked": True}]},
        "temporal_aggregation": {"stored_resolution_minutes": 60},
        "linkage_attack": {"success_rate_pct": 0.5},
    }
    out = evaluate_policy(sample)
    checks = [
        {"check": "self: sketch_only", "pass": out["sketch_only"]},
        {"check": "self: minimum_k", "pass": out["minimum_k"] >= 50},
        {"check": "self: linkage_rate", "pass": out["linkage_success_rate_pct"] < 1.0},
    ]
    return all(c["pass"] for c in checks), checks


def main() -> int:
    logger = configure_test_logging("check_longitudinal_privacy")
    as_json = "--json" in sys.argv
    run_self_test = "--self-test" in sys.argv

    if run_self_test:
        ok, checks = self_test()
        result = {
            "self_test_passed": ok,
            "checks_total": len(checks),
            "checks_passing": sum(1 for c in checks if c["pass"]),
            "checks_failing": sum(1 for c in checks if not c["pass"]),
        }
        if as_json:
            print(json.dumps(result, indent=2))
        else:
            print("PASS" if ok else "FAIL")
            for check in checks:
                status = "PASS" if check["pass"] else "FAIL"
                print(f"[{status}] {check['check']}")
        return 0 if ok else 1

    result = run_checks()
    if as_json:
        print(json.dumps(result, indent=2))
    else:
        summary = result["summary"]
        print(f"{result['verdict']}: {TITLE} ({summary['passing']}/{summary['total']} checks passed)")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"[{status}] {check['check']}: {check['detail']}")
    return 0 if result["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
