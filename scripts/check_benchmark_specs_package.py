#!/usr/bin/env python3
"""Verify bd-3h1g benchmark specs/harness/datasets/scoring package."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

BEAD_ID = "bd-3h1g"
SECTION = "14"
TITLE = "Publish benchmark specs/harness/datasets/scoring formulas"

CONTRACT = ROOT / "docs" / "specs" / "section_14" / "bd-3h1g_contract.md"
PACKAGE = ROOT / "artifacts" / "14" / "benchmark_specs_package.json"

REQUIRED_TRACK_IDS = {
    "compatibility_correctness",
    "security_trust",
    "performance_under_hardening",
    "containment_revocation_latency",
    "replay_determinism",
    "adversarial_resilience",
}

REQUIRED_EVENT_CODES = {
    "BSP-001",
    "BSP-002",
    "BSP-003",
    "BSP-004",
    "BSP-005",
    "BSP-006",
}

CHECKS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("ok" if passed else "failed"),
    }
    CHECKS.append(entry)
    return entry


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _trace_id(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _safe_rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _compute_overall_score(track_weights: dict[str, float], scores: dict[str, float]) -> float:
    total = 0.0
    for track_id, weight in track_weights.items():
        total += weight * scores[track_id]
    return round(total, 4)


def _passes_score_gate(
    scores: dict[str, float],
    track_weights: dict[str, float],
    minimum_track_score: float,
    minimum_overall_score: float,
) -> bool:
    if any(score < minimum_track_score for score in scores.values()):
        return False
    return _compute_overall_score(track_weights, scores) >= minimum_overall_score


def sample_package() -> dict[str, Any]:
    return {
        "bead_id": BEAD_ID,
        "generated_at_utc": "2026-02-21T01:20:00Z",
        "spec_version": "1.0.0",
        "trace_id": "7c2a9a6bf59b252029a96e6cce5f5964da8f8b63253f10c1175dbf72e6c7a110",
        "benchmark_tracks": [
            {
                "track_id": "compatibility_correctness",
                "display_name": "Compatibility and Correctness",
                "weight": 0.22,
                "metric_ids": ["api_behavior_equivalence_rate", "compat_golden_pass_rate"],
                "pass_threshold": 0.95,
            },
            {
                "track_id": "security_trust",
                "display_name": "Security and Trust",
                "weight": 0.20,
                "metric_ids": ["policy_enforcement_precision", "unauthorized_action_block_rate"],
                "pass_threshold": 0.90,
            },
            {
                "track_id": "performance_under_hardening",
                "display_name": "Performance Under Hardening",
                "weight": 0.18,
                "metric_ids": ["latency_p95_budget_pass_rate", "latency_p99_budget_pass_rate"],
                "pass_threshold": 0.85,
            },
            {
                "track_id": "containment_revocation_latency",
                "display_name": "Containment and Revocation Latency",
                "weight": 0.15,
                "metric_ids": ["containment_convergence_pass_rate", "revocation_freshness_pass_rate"],
                "pass_threshold": 0.88,
            },
            {
                "track_id": "replay_determinism",
                "display_name": "Replay Determinism",
                "weight": 0.13,
                "metric_ids": ["artifact_replay_hash_match_rate", "decision_replay_equivalence_rate"],
                "pass_threshold": 0.90,
            },
            {
                "track_id": "adversarial_resilience",
                "display_name": "Adversarial Resilience",
                "weight": 0.12,
                "metric_ids": ["redteam_detection_recall", "policy_bypass_resistance_rate"],
                "pass_threshold": 0.85,
            },
        ],
        "harness": {
            "runner_command": "scripts/run_benchmark_campaign.sh --manifest fixtures/benchmarks/campaign_manifest.json",
            "seed_policy": "fixed-seed-per-track",
            "determinism_replays": 5,
            "warmup_runs": 3,
            "measured_runs": 12,
            "isolation_mode": "containerized",
        },
        "datasets": [
            {
                "dataset_id": "compat_golden_v1",
                "track_id": "compatibility_correctness",
                "source_uri": "fixtures/benchmarks/datasets/compat_golden_v1.jsonl",
                "records": 2400,
                "sha256": "7b8d650f16c66e0f52fc6b0309f6f1dbde402bcfce2f6dd8766a2ccbbfd7f43a",
                "license": "CC-BY-4.0",
            },
            {
                "dataset_id": "security_trust_eval_v1",
                "track_id": "security_trust",
                "source_uri": "fixtures/benchmarks/datasets/security_trust_eval_v1.jsonl",
                "records": 1800,
                "sha256": "d6f0a0e4f41beeb7d3e1000999853b58ed42af17f60730ad3f6a8cad4f4cf9f8",
                "license": "CC-BY-4.0",
            },
            {
                "dataset_id": "hardening_perf_hotpath_v1",
                "track_id": "performance_under_hardening",
                "source_uri": "fixtures/benchmarks/datasets/hardening_perf_hotpath_v1.jsonl",
                "records": 3200,
                "sha256": "ccebd7cf9a3c1c1dcadf6f65ea0aca3404f808faddf1f80ad8ec6f487390c6d4",
                "license": "CC-BY-4.0",
            },
            {
                "dataset_id": "containment_revocation_v1",
                "track_id": "containment_revocation_latency",
                "source_uri": "fixtures/benchmarks/datasets/containment_revocation_v1.jsonl",
                "records": 1500,
                "sha256": "6b4c558f18dbf8f2f3a63da398f945c38b4f01d713863263ee7034f6e7305f0c",
                "license": "CC-BY-4.0",
            },
            {
                "dataset_id": "replay_determinism_v1",
                "track_id": "replay_determinism",
                "source_uri": "fixtures/benchmarks/datasets/replay_determinism_v1.jsonl",
                "records": 2100,
                "sha256": "f0607b289fe6c1053ed6cd65fffcd6786fef6dc0458f8b91c8645f98059d95e0",
                "license": "CC-BY-4.0",
            },
            {
                "dataset_id": "adversarial_resilience_v1",
                "track_id": "adversarial_resilience",
                "source_uri": "fixtures/benchmarks/datasets/adversarial_resilience_v1.jsonl",
                "records": 1700,
                "sha256": "4efa2387576da507fd32f04ac5cb4fe5144fbe31e39446985503ce203897a2c0",
                "license": "CC-BY-4.0",
            },
        ],
        "scoring_formula": {
            "normalization": "score in [0,1] from normalized metric aggregations",
            "aggregate_formula": "aggregate_score = sum(weight_i * score_i)",
            "minimum_track_score": 0.75,
            "minimum_overall_score": 0.85,
            "hard_fail_conditions": [
                "any_track_below_minimum_track_score",
                "overall_below_minimum_overall_score",
                "missing_required_track_or_dataset",
            ],
        },
        "sample_scores": {
            "compatibility_correctness": 0.96,
            "security_trust": 0.94,
            "performance_under_hardening": 0.88,
            "containment_revocation_latency": 0.90,
            "replay_determinism": 0.93,
            "adversarial_resilience": 0.89,
        },
        "sample_overall_score": 0.9203,
        "release_report_fields": [
            "benchmark_run_id",
            "track_scores",
            "aggregate_score",
            "pass_fail_verdict",
            "seed_manifest_hash",
            "dataset_hash_manifest",
            "environment_fingerprint",
            "trace_id",
        ],
        "event_codes": sorted(REQUIRED_EVENT_CODES),
    }


def run_checks(contract_path: Path = CONTRACT, package_path: Path = PACKAGE) -> dict[str, Any]:
    CHECKS.clear()
    events: list[dict[str, Any]] = []

    _check("file: contract", contract_path.is_file(), _safe_rel(contract_path))
    _check("file: benchmark package", package_path.is_file(), _safe_rel(package_path))

    contract_text = ""
    if contract_path.is_file():
        contract_text = contract_path.read_text(encoding="utf-8")
    required_contract_tokens = [
        "INV-BSP-TRACK-COVERAGE",
        "INV-BSP-TRACK-WEIGHTS",
        "INV-BSP-HARNESS-REPRO",
        "INV-BSP-DATASET-INTEGRITY",
        "INV-BSP-SCORING-FORMULA",
        "INV-BSP-QUALITY-GATES",
        "INV-BSP-DETERMINISM",
        "INV-BSP-ADVERSARIAL",
    ]
    _check(
        "contract invariants present",
        all(token in contract_text for token in required_contract_tokens),
        "all invariants present" if all(token in contract_text for token in required_contract_tokens) else "missing invariant token(s)",
    )
    _check(
        "contract event codes present",
        all(code in contract_text for code in REQUIRED_EVENT_CODES),
        "all event codes present" if all(code in contract_text for code in REQUIRED_EVENT_CODES) else "missing event code(s)",
    )

    package: dict[str, Any] = {}
    parse_error = ""
    if package_path.is_file():
        try:
            package = json.loads(package_path.read_text(encoding="utf-8"))
            if not isinstance(package, dict):
                parse_error = "package root must be object"
        except json.JSONDecodeError as exc:
            parse_error = f"invalid package JSON: {exc}"
    _check("package JSON parse", parse_error == "", parse_error or "ok")

    if parse_error:
        total = len(CHECKS)
        passed = sum(1 for check in CHECKS if check["pass"])
        failed = total - passed
        return {
            "bead_id": BEAD_ID,
            "title": TITLE,
            "section": SECTION,
            "verdict": "FAIL",
            "total": total,
            "passed": passed,
            "failed": failed,
            "checks": CHECKS,
            "events": [],
        }

    required_top = (
        "bead_id",
        "generated_at_utc",
        "spec_version",
        "trace_id",
        "benchmark_tracks",
        "harness",
        "datasets",
        "scoring_formula",
        "sample_scores",
        "sample_overall_score",
        "event_codes",
    )
    missing_top = [field for field in required_top if field not in package]
    _check(
        "package required top-level fields",
        len(missing_top) == 0,
        "missing: " + ", ".join(missing_top) if missing_top else "ok",
    )
    _check("package bead_id", package.get("bead_id") == BEAD_ID)
    _check(
        "trace_id format",
        isinstance(package.get("trace_id"), str) and re.fullmatch(r"[0-9a-f]{64}", str(package.get("trace_id", ""))) is not None,
    )

    tracks = package.get("benchmark_tracks")
    track_weights: dict[str, float] = {}
    track_errors: list[str] = []
    track_ids: list[str] = []
    if isinstance(tracks, list):
        for idx, track in enumerate(tracks):
            if not isinstance(track, dict):
                track_errors.append(f"benchmark_tracks[{idx}] must be object")
                continue
            for field in ("track_id", "display_name", "weight", "metric_ids", "pass_threshold"):
                if field not in track:
                    track_errors.append(f"benchmark_tracks[{idx}] missing field: {field}")

            track_id = track.get("track_id")
            if not isinstance(track_id, str) or not track_id:
                track_errors.append(f"benchmark_tracks[{idx}].track_id must be non-empty string")
                continue
            track_ids.append(track_id)

            weight = track.get("weight")
            if not isinstance(weight, (int, float)) or weight <= 0 or weight > 1:
                track_errors.append(f"benchmark_tracks[{idx}].weight must be in (0,1]")
            else:
                track_weights[track_id] = float(weight)

            metric_ids = track.get("metric_ids")
            metric_ok = isinstance(metric_ids, list) and len(metric_ids) >= 2 and all(
                isinstance(metric_id, str) and metric_id for metric_id in metric_ids
            )
            if not metric_ok:
                track_errors.append(f"benchmark_tracks[{idx}].metric_ids must contain >=2 non-empty strings")

            threshold = track.get("pass_threshold")
            if not isinstance(threshold, (int, float)) or threshold <= 0 or threshold > 1:
                track_errors.append(f"benchmark_tracks[{idx}].pass_threshold must be in (0,1]")
    else:
        track_errors.append("benchmark_tracks must be list")

    _check("track schema", len(track_errors) == 0, "; ".join(track_errors[:5]) if track_errors else "ok")
    _check(
        "required track coverage exact",
        set(track_ids) == REQUIRED_TRACK_IDS and len(track_ids) == len(REQUIRED_TRACK_IDS),
        f"seen={sorted(set(track_ids))}",
    )
    _check(
        "track weights sum to 1.0",
        abs(sum(track_weights.values()) - 1.0) <= 1e-9 and len(track_weights) == len(REQUIRED_TRACK_IDS),
        f"sum={sum(track_weights.values()):.10f}",
    )

    harness = package.get("harness", {})
    harness_ok = isinstance(harness, dict)
    harness_checks = {
        "runner_command": isinstance(harness.get("runner_command"), str) and harness.get("runner_command", "").strip() != "",
        "seed_policy": isinstance(harness.get("seed_policy"), str) and harness.get("seed_policy", "").strip() != "",
        "determinism_replays": isinstance(harness.get("determinism_replays"), int) and harness.get("determinism_replays") >= 3,
        "warmup_runs": isinstance(harness.get("warmup_runs"), int) and harness.get("warmup_runs") >= 1,
        "measured_runs": isinstance(harness.get("measured_runs"), int) and harness.get("measured_runs") >= 5,
        "isolation_mode": harness.get("isolation_mode") in {"containerized", "vm"},
    }
    harness_ok = harness_ok and all(harness_checks.values())
    _check("harness deterministic controls", harness_ok, "ok" if harness_ok else str(harness_checks))

    datasets = package.get("datasets")
    dataset_errors: list[str] = []
    dataset_track_ids: set[str] = set()
    dataset_ids: list[str] = []
    if isinstance(datasets, list):
        for idx, dataset in enumerate(datasets):
            if not isinstance(dataset, dict):
                dataset_errors.append(f"datasets[{idx}] must be object")
                continue
            for field in ("dataset_id", "track_id", "source_uri", "records", "sha256", "license"):
                if field not in dataset:
                    dataset_errors.append(f"datasets[{idx}] missing field: {field}")
            dataset_id = dataset.get("dataset_id")
            track_id = dataset.get("track_id")
            if isinstance(dataset_id, str):
                dataset_ids.append(dataset_id)
            if isinstance(track_id, str):
                dataset_track_ids.add(track_id)
            records = dataset.get("records")
            if not isinstance(records, int) or records < 1000:
                dataset_errors.append(f"datasets[{idx}].records must be integer >=1000")
            sha256 = dataset.get("sha256", "")
            if not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
                dataset_errors.append(f"datasets[{idx}].sha256 must be 64-char lowercase hex")
    else:
        dataset_errors.append("datasets must be list")

    _check("dataset schema and integrity fields", len(dataset_errors) == 0, "; ".join(dataset_errors[:5]) if dataset_errors else "ok")
    _check(
        "dataset ids unique",
        len(dataset_ids) == len(set(dataset_ids)) and len(dataset_ids) >= len(REQUIRED_TRACK_IDS),
        f"count={len(dataset_ids)} unique={len(set(dataset_ids))}",
    )
    _check(
        "dataset track coverage exact",
        dataset_track_ids == REQUIRED_TRACK_IDS,
        f"seen={sorted(dataset_track_ids)}",
    )

    scoring = package.get("scoring_formula", {})
    scoring_ok = isinstance(scoring, dict)
    required_scoring = ("normalization", "aggregate_formula", "minimum_track_score", "minimum_overall_score", "hard_fail_conditions")
    missing_scoring = [field for field in required_scoring if field not in scoring]
    scoring_ok = scoring_ok and len(missing_scoring) == 0
    aggregate_formula = str(scoring.get("aggregate_formula", ""))
    scoring_ok = scoring_ok and ("sum" in aggregate_formula and "weight" in aggregate_formula and "score" in aggregate_formula)
    min_track = scoring.get("minimum_track_score")
    min_overall = scoring.get("minimum_overall_score")
    scoring_ok = scoring_ok and isinstance(min_track, (int, float)) and isinstance(min_overall, (int, float))
    scoring_ok = scoring_ok and 0 < float(min_track) <= 1 and 0 < float(min_overall) <= 1 and float(min_overall) >= float(min_track)
    _check(
        "scoring formula contract",
        scoring_ok,
        "missing=" + ",".join(missing_scoring) if missing_scoring else "ok",
    )

    sample_scores = package.get("sample_scores", {})
    sample_ok = isinstance(sample_scores, dict)
    sample_missing = sorted(REQUIRED_TRACK_IDS - set(sample_scores.keys() if isinstance(sample_scores, dict) else set()))
    if sample_ok:
        for track_id in REQUIRED_TRACK_IDS:
            value = sample_scores.get(track_id)
            if not isinstance(value, (int, float)) or value < 0 or value > 1:
                sample_ok = False
    sample_ok = sample_ok and len(sample_missing) == 0
    _check(
        "sample scores cover required tracks",
        sample_ok,
        "missing=" + ",".join(sample_missing) if sample_missing else "ok",
    )

    computed_overall = _compute_overall_score(track_weights, {k: float(v) for k, v in sample_scores.items()}) if sample_ok else 0.0
    declared_overall = package.get("sample_overall_score")
    _check(
        "sample overall score matches weighted sum",
        isinstance(declared_overall, (int, float)) and abs(float(declared_overall) - computed_overall) <= 1e-4,
        f"declared={declared_overall} computed={computed_overall}",
    )

    gate_pass = False
    if sample_ok and isinstance(min_track, (int, float)) and isinstance(min_overall, (int, float)):
        gate_pass = _passes_score_gate(
            {track: float(score) for track, score in sample_scores.items()},
            track_weights,
            float(min_track),
            float(min_overall),
        )
    _check("sample score gates pass", gate_pass, f"overall={computed_overall}")

    reversed_weights = {item["track_id"]: float(item["weight"]) for item in reversed(tracks)} if isinstance(tracks, list) else {}
    reversed_overall = _compute_overall_score(reversed_weights, {k: float(v) for k, v in sample_scores.items()}) if reversed_weights else 0.0
    _check(
        "determinism under track reordering",
        abs(reversed_overall - computed_overall) <= 1e-9,
        f"forward={computed_overall} reversed={reversed_overall}",
    )

    adversarial_ok = False
    if sample_ok and isinstance(min_track, (int, float)) and isinstance(min_overall, (int, float)):
        perturbed = {track: float(score) for track, score in sample_scores.items()}
        target_track = sorted(REQUIRED_TRACK_IDS)[0]
        perturbed[target_track] = max(0.0, float(min_track) - 0.05)
        adversarial_ok = not _passes_score_gate(
            perturbed,
            track_weights,
            float(min_track),
            float(min_overall),
        )
    _check(
        "adversarial perturbation flips verdict to fail",
        adversarial_ok,
        "ok" if adversarial_ok else "perturbation did not fail gate",
    )

    package_event_codes = set(package.get("event_codes", [])) if isinstance(package.get("event_codes"), list) else set()
    _check(
        "package event code coverage",
        package_event_codes == REQUIRED_EVENT_CODES,
        f"seen={sorted(package_event_codes)}",
    )

    trace = package.get("trace_id")
    if not isinstance(trace, str) or re.fullmatch(r"[0-9a-f]{64}", trace) is None:
        trace = _trace_id(package)

    events.append({"event_code": "BSP-001", "trace_id": trace, "message": "Benchmark package loaded."})
    events.append({"event_code": "BSP-002", "trace_id": trace, "message": "Contract fields and invariants validated."})
    events.append({"event_code": "BSP-003", "trace_id": trace, "message": "Scoring formula validated."})
    events.append({"event_code": "BSP-004", "trace_id": trace, "message": "Determinism check executed."})
    events.append({"event_code": "BSP-005", "trace_id": trace, "message": "Adversarial perturbation check executed."})

    verdict = "PASS" if all(check["pass"] for check in CHECKS) else "FAIL"
    events.append({"event_code": "BSP-006", "trace_id": trace, "message": f"Final verdict emitted: {verdict}."})

    total = len(CHECKS)
    passed = sum(1 for check in CHECKS if check["pass"])
    failed = total - passed

    return {
        "bead_id": BEAD_ID,
        "title": TITLE,
        "section": SECTION,
        "trace_id": trace,
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "computed": {
            "required_tracks": sorted(REQUIRED_TRACK_IDS),
            "track_weight_sum": round(sum(track_weights.values()), 10),
            "sample_overall_score": computed_overall,
            "minimum_track_score": min_track,
            "minimum_overall_score": min_overall,
        },
        "checks": CHECKS,
        "events": events,
    }


def self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="bd-3h1g-self-test-") as tmp:
        root = Path(tmp)
        contract_path = root / "contract.md"
        package_path = root / "package.json"

        contract_path.write_text(
            "\n".join(
                [
                    "# test contract",
                    "INV-BSP-TRACK-COVERAGE",
                    "INV-BSP-TRACK-WEIGHTS",
                    "INV-BSP-HARNESS-REPRO",
                    "INV-BSP-DATASET-INTEGRITY",
                    "INV-BSP-SCORING-FORMULA",
                    "INV-BSP-QUALITY-GATES",
                    "INV-BSP-DETERMINISM",
                    "INV-BSP-ADVERSARIAL",
                    *sorted(REQUIRED_EVENT_CODES),
                ]
            ),
            encoding="utf-8",
        )

        passing_package = sample_package()
        package_path.write_text(json.dumps(passing_package, indent=2), encoding="utf-8")
        pass_result = run_checks(contract_path=contract_path, package_path=package_path)
        if pass_result["verdict"] != "PASS":
            return False

        failing_package = sample_package()
        failing_package["benchmark_tracks"][0]["weight"] = 0.5
        package_path.write_text(json.dumps(failing_package, indent=2), encoding="utf-8")
        fail_result = run_checks(contract_path=contract_path, package_path=package_path)
        return fail_result["verdict"] == "FAIL"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    parser.add_argument("--self-test", action="store_true", help="Run deterministic internal self-test.")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        payload = {"ok": ok, "self_test": "passed" if ok else "failed"}
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(payload["self_test"])
        return 0 if ok else 1

    result = run_checks()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[{result['verdict']}] {TITLE}")
        print(f"passed={result['passed']} failed={result['failed']} total={result['total']}")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"- {status}: {check['check']} ({check['detail']})")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
