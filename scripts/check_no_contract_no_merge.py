#!/usr/bin/env python3
"""Validate Section 11 no-contract-no-merge gate (bd-2ut3)."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

TEMPLATE_PATH = ROOT / "docs" / "templates" / "change_summary_template.md"
EXAMPLE_PATH = ROOT / "docs" / "change_summaries" / "example_change_summary.json"
DEFAULT_SUMMARY_DIR = ROOT / "docs" / "change_summaries"

REQUIRED_EVENT_CODES = {
    "CONTRACT_NO_MERGE_VALIDATED",
    "CONTRACT_NO_MERGE_MISSING",
    "CONTRACT_NO_MERGE_INCOMPLETE",
    "CONTRACT_NO_MERGE_OVERRIDE",
}

SUBSYSTEM_PATH_PREFIXES = (
    "crates/franken-node/src/",
    "crates/franken-engine/src/",
    "crates/asupersync/src/",
    "services/",
)

REQUIRED_BASE_FIELDS = (
    "intent",
    "scope",
    "surface_area_delta",
    "affected_contracts",
    "operational_impact",
    "risk_delta",
    "compatibility",
    "dependency_changes",
)

REQUIRED_THREAT_VECTORS = {
    "privilege_escalation",
    "data_exfiltration",
    "denial_of_service",
}
RISK_LEVELS = {"low", "medium", "high", "critical"}
EV_TIERS = {"T0", "T1", "T2", "T3", "T4"}
IMPACT_UNITS = {"dollars", "hours", "severity_units"}
LOSS_CATEGORIES = {"negligible", "minor", "moderate", "major", "catastrophic"}
ROLLBACK_MECHANISMS = {"automatic", "semi-automatic", "manual"}
WEDGE_STATES = {"PENDING", "ACTIVE", "PAUSED", "ROLLED_BACK", "COMPLETE"}
INCREMENT_POLICIES = {"linear", "exponential", "manual"}
WEDGE_STAGE_FIELDS = (
    "stage_id",
    "target_percentage",
    "duration_hours",
    "success_criteria",
    "rollback_trigger",
)

PLACEHOLDER_PATTERNS = (
    re.compile(r"<[^>]+>"),
    re.compile(r"\$\{[^}]+\}"),
    re.compile(r"\{\{[^}]+\}\}"),
    re.compile(r"%[sd]"),
    re.compile(r"\bTODO\b", re.IGNORECASE),
)
DURATION_TOKEN_RE = re.compile(r"\d+[hms]")
DURATION_RE = re.compile(r"^(?:(?:\d+h)?(?:\d+m)?(?:\d+s)?)$")
DELTA_EPSILON = 1e-9


def _norm(path: Path | str) -> str:
    return str(path).replace("\\", "/")


def _rel(path: Path, base: Path) -> str:
    try:
        return _norm(path.relative_to(base))
    except ValueError:
        return _norm(path)


def _trace_id(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load_changed_files(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"changed-files list not found: {path}")
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _discover_changed_files_from_git(project_root: Path) -> list[str]:
    commands = [
        ["git", "-C", str(project_root), "diff", "--name-only", "origin/main...HEAD"],
        ["git", "-C", str(project_root), "diff", "--name-only", "HEAD~1...HEAD"],
    ]
    last_error: Exception | None = None
    for cmd in commands:
        try:
            proc = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
            )
            return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        except Exception as exc:  # pragma: no cover - defensive fallback
            last_error = exc
    raise RuntimeError(f"unable to discover changed files via git diff: {last_error}")


def _is_subsystem_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in SUBSYSTEM_PATH_PREFIXES)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _require_non_empty_str(value: Any, field: str, errors: list[str]) -> str:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{field} must be a non-empty string")
        return ""
    return value.strip()


def _require_list(value: Any, field: str, errors: list[str], *, min_items: int = 0) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{field} must be a list")
        return []
    if len(value) < min_items:
        errors.append(f"{field} must contain at least {min_items} item(s)")
    return value


def _contains_placeholder(command: str) -> bool:
    return any(pattern.search(command) for pattern in PLACEHOLDER_PATTERNS)


def _valid_duration(duration: str) -> bool:
    if DURATION_RE.fullmatch(duration) is None:
        return False
    return len(DURATION_TOKEN_RE.findall(duration)) > 0


def _score_to_tier(score: int) -> str:
    if score >= 80:
        return "T4"
    if score >= 60:
        return "T3"
    if score >= 40:
        return "T2"
    if score >= 20:
        return "T1"
    return "T0"


def _classify_loss(aggregate: float) -> str:
    if aggregate >= 100_000:
        return "catastrophic"
    if aggregate >= 10_000:
        return "major"
    if aggregate >= 1_000:
        return "moderate"
    if aggregate >= 100:
        return "minor"
    return "negligible"


def _validate_artifact_path(
    *,
    artifact_path: str,
    field: str,
    project_root: Path,
    errors: list[str],
    required_prefix: str | None = None,
) -> bool:
    if required_prefix is not None and not artifact_path.startswith(required_prefix):
        errors.append(f"{field} must start with {required_prefix}")
        return False

    artifact_abs = project_root / artifact_path
    if not artifact_abs.is_file():
        errors.append(f"{field} does not exist: {artifact_path}")
        return False

    return True


def _validate_base_fields(change_summary: dict[str, Any], errors: list[str]) -> None:
    for field in REQUIRED_BASE_FIELDS:
        value = change_summary.get(field)
        if value is None:
            errors.append(f"change_summary.{field} is required")
            continue
        if field == "intent":
            _require_non_empty_str(value, "change_summary.intent", errors)
        elif field in {"scope", "surface_area_delta", "affected_contracts", "operational_impact", "risk_delta", "compatibility", "dependency_changes"}:
            if not isinstance(value, dict):
                errors.append(f"change_summary.{field} must be an object")


def _validate_compat_threat(change_summary: dict[str, Any], project_root: Path, errors: list[str]) -> None:
    path = "change_summary.compatibility_and_threat_evidence"
    compat = change_summary.get("compatibility_and_threat_evidence")
    if not isinstance(compat, dict):
        errors.append(f"{path} must be an object")
        return

    suites = _require_list(compat.get("compatibility_test_suites"), f"{path}.compatibility_test_suites", errors, min_items=1)
    for idx, suite in enumerate(suites):
        prefix = f"{path}.compatibility_test_suites[{idx}]"
        if not isinstance(suite, dict):
            errors.append(f"{prefix} must be an object")
            continue
        _require_non_empty_str(suite.get("suite_name"), f"{prefix}.suite_name", errors)
        pass_count = suite.get("pass_count")
        fail_count = suite.get("fail_count")
        if not isinstance(pass_count, int) or isinstance(pass_count, bool) or pass_count < 0:
            errors.append(f"{prefix}.pass_count must be an integer >= 0")
        if not isinstance(fail_count, int) or isinstance(fail_count, bool) or fail_count < 0:
            errors.append(f"{prefix}.fail_count must be an integer >= 0")
        if isinstance(pass_count, int) and isinstance(fail_count, int) and pass_count + fail_count == 0:
            errors.append(f"{prefix} must report at least one test result")
        artifact_path = _require_non_empty_str(suite.get("artifact_path"), f"{prefix}.artifact_path", errors)
        if artifact_path:
            _validate_artifact_path(
                artifact_path=artifact_path,
                field=f"{prefix}.artifact_path",
                project_root=project_root,
                errors=errors,
                required_prefix="artifacts/",
            )

    risk = compat.get("regression_risk_assessment")
    if not isinstance(risk, dict):
        errors.append(f"{path}.regression_risk_assessment must be an object")
    else:
        risk_level = _require_non_empty_str(risk.get("risk_level"), f"{path}.regression_risk_assessment.risk_level", errors)
        if risk_level and risk_level not in RISK_LEVELS:
            errors.append(f"{path}.regression_risk_assessment.risk_level must be one of: {', '.join(sorted(RISK_LEVELS))}")
        api_families = _require_list(risk.get("api_families"), f"{path}.regression_risk_assessment.api_families", errors, min_items=1)
        for i, family in enumerate(api_families):
            if not isinstance(family, str) or not family.strip():
                errors.append(f"{path}.regression_risk_assessment.api_families[{i}] must be a non-empty string")
        _require_non_empty_str(risk.get("notes"), f"{path}.regression_risk_assessment.notes", errors)

    vectors = _require_list(compat.get("threat_vectors"), f"{path}.threat_vectors", errors, min_items=1)
    seen_required: set[str] = set()
    for idx, entry in enumerate(vectors):
        prefix = f"{path}.threat_vectors[{idx}]"
        if not isinstance(entry, dict):
            errors.append(f"{prefix} must be an object")
            continue
        vector = _require_non_empty_str(entry.get("vector"), f"{prefix}.vector", errors)
        mitigation = _require_non_empty_str(entry.get("mitigation"), f"{prefix}.mitigation", errors)
        if vector in REQUIRED_THREAT_VECTORS and mitigation:
            seen_required.add(vector)

    missing_vectors = sorted(REQUIRED_THREAT_VECTORS - seen_required)
    if missing_vectors:
        errors.append(f"{path}.threat_vectors missing required vector(s): {', '.join(missing_vectors)}")


def _validate_ev_score(change_summary: dict[str, Any], project_root: Path, errors: list[str]) -> None:
    path = "change_summary.ev_score_and_tier"
    ev = change_summary.get("ev_score_and_tier")
    if not isinstance(ev, dict):
        errors.append(f"{path} must be an object")
        return

    ev_score = ev.get("ev_score")
    if not _is_number(ev_score) or not (0 <= float(ev_score) <= 100):
        errors.append(f"{path}.ev_score must be numeric in range 0..100")

    tier = _require_non_empty_str(ev.get("tier"), f"{path}.tier", errors)
    if tier and tier not in EV_TIERS:
        errors.append(f"{path}.tier must be one of: {', '.join(sorted(EV_TIERS))}")

    if _is_number(ev_score) and tier in EV_TIERS:
        expected_tier = _score_to_tier(int(float(ev_score)))
        if tier != expected_tier:
            errors.append(f"{path}.tier must match ev_score ({ev_score} -> {expected_tier}, got {tier})")

    dimensions = ev.get("dimension_scores")
    if not isinstance(dimensions, dict):
        errors.append(f"{path}.dimension_scores must be an object")
    else:
        required_dimensions = ("code_review", "test_coverage", "security_audit", "supply_chain", "conformance")
        for dim in required_dimensions:
            entry = dimensions.get(dim)
            if not isinstance(entry, dict):
                errors.append(f"{path}.dimension_scores.{dim} must be an object")
                continue
            score = entry.get("score")
            if not _is_number(score) or not (0 <= float(score) <= 1):
                errors.append(f"{path}.dimension_scores.{dim}.score must be numeric in range 0..1")
            evidence_ref = _require_non_empty_str(entry.get("evidence_ref"), f"{path}.dimension_scores.{dim}.evidence_ref", errors)
            if evidence_ref:
                _validate_artifact_path(
                    artifact_path=evidence_ref,
                    field=f"{path}.dimension_scores.{dim}.evidence_ref",
                    project_root=project_root,
                    errors=errors,
                    required_prefix="artifacts/",
                )
            _require_non_empty_str(entry.get("assessed_at"), f"{path}.dimension_scores.{dim}.assessed_at", errors)

    _require_non_empty_str(ev.get("rationale"), f"{path}.rationale", errors)


def _validate_expected_loss(change_summary: dict[str, Any], errors: list[str]) -> None:
    path = "change_summary.expected_loss_model"
    elm = change_summary.get("expected_loss_model")
    if not isinstance(elm, dict):
        errors.append(f"{path} must be an object")
        return

    scenarios = _require_list(elm.get("scenarios"), f"{path}.scenarios", errors, min_items=3)
    computed_aggregate = 0.0
    for idx, scenario in enumerate(scenarios):
        prefix = f"{path}.scenarios[{idx}]"
        if not isinstance(scenario, dict):
            errors.append(f"{prefix} must be an object")
            continue
        _require_non_empty_str(scenario.get("name"), f"{prefix}.name", errors)

        probability = scenario.get("probability")
        impact_value = scenario.get("impact_value")
        impact_unit = scenario.get("impact_unit")
        if not _is_number(probability) or not (0 <= float(probability) <= 1):
            errors.append(f"{prefix}.probability must be numeric in range 0..1")
        if not _is_number(impact_value) or float(impact_value) < 0:
            errors.append(f"{prefix}.impact_value must be non-negative numeric")
        if not isinstance(impact_unit, str) or impact_unit not in IMPACT_UNITS:
            errors.append(f"{prefix}.impact_unit must be one of: {', '.join(sorted(IMPACT_UNITS))}")
        _require_non_empty_str(scenario.get("mitigation"), f"{prefix}.mitigation", errors)

        if _is_number(probability) and _is_number(impact_value):
            computed_aggregate += float(probability) * float(impact_value)

    aggregate = elm.get("aggregate_expected_loss")
    if not _is_number(aggregate) or float(aggregate) < 0:
        errors.append(f"{path}.aggregate_expected_loss must be non-negative numeric")
    elif abs(float(aggregate) - computed_aggregate) > 1e-6:
        errors.append(
            f"{path}.aggregate_expected_loss must equal sum(probability * impact_value) "
            f"(expected {computed_aggregate}, got {aggregate})"
        )

    ci = elm.get("confidence_interval")
    if not isinstance(ci, dict):
        errors.append(f"{path}.confidence_interval must be an object")
    else:
        lower = ci.get("lower")
        upper = ci.get("upper")
        level = ci.get("confidence_level")
        if not _is_number(lower) or float(lower) < 0:
            errors.append(f"{path}.confidence_interval.lower must be non-negative numeric")
        if not _is_number(upper) or float(upper) < 0:
            errors.append(f"{path}.confidence_interval.upper must be non-negative numeric")
        if not _is_number(level) or not (0 < float(level) < 1):
            errors.append(f"{path}.confidence_interval.confidence_level must be numeric in range (0,1)")
        if _is_number(lower) and _is_number(upper) and float(lower) > float(upper):
            errors.append(f"{path}.confidence_interval lower must be <= upper")
        if _is_number(aggregate) and _is_number(lower) and _is_number(upper):
            if not (float(lower) <= float(aggregate) <= float(upper)):
                errors.append(f"{path}.aggregate_expected_loss must lie within confidence_interval bounds")

    loss_category = _require_non_empty_str(elm.get("loss_category"), f"{path}.loss_category", errors)
    if loss_category and loss_category not in LOSS_CATEGORIES:
        errors.append(f"{path}.loss_category must be one of: {', '.join(sorted(LOSS_CATEGORIES))}")
    if _is_number(aggregate) and loss_category in LOSS_CATEGORIES:
        expected_category = _classify_loss(float(aggregate))
        if loss_category != expected_category:
            errors.append(f"{path}.loss_category must match aggregate_expected_loss ({aggregate} -> {expected_category}, got {loss_category})")


def _validate_fallback_trigger(change_summary: dict[str, Any], errors: list[str]) -> None:
    path = "change_summary.fallback_trigger"
    fallback = change_summary.get("fallback_trigger")
    if not isinstance(fallback, dict):
        errors.append(f"{path} must be an object")
        return

    triggers = _require_list(fallback.get("trigger_conditions"), f"{path}.trigger_conditions", errors, min_items=1)
    for idx, trigger in enumerate(triggers):
        if not isinstance(trigger, str) or not trigger.strip():
            errors.append(f"{path}.trigger_conditions[{idx}] must be a non-empty string")

    _require_non_empty_str(fallback.get("fallback_target_state"), f"{path}.fallback_target_state", errors)

    mechanism = _require_non_empty_str(fallback.get("rollback_mechanism"), f"{path}.rollback_mechanism", errors)
    if mechanism and mechanism not in ROLLBACK_MECHANISMS:
        errors.append(f"{path}.rollback_mechanism must be one of: {', '.join(sorted(ROLLBACK_MECHANISMS))}")

    max_detection = fallback.get("max_detection_latency_s")
    if not _is_number(max_detection) or not (0 < float(max_detection) <= 5):
        errors.append(f"{path}.max_detection_latency_s must be numeric and <= 5")

    rto = fallback.get("recovery_time_objective_s")
    if not _is_number(rto) or not (0 < float(rto) <= 30):
        errors.append(f"{path}.recovery_time_objective_s must be numeric and <= 30")

    _require_non_empty_str(fallback.get("subsystem_id"), f"{path}.subsystem_id", errors)
    _require_non_empty_str(fallback.get("rationale"), f"{path}.rationale", errors)


def _validate_rollout_wedge(payload: dict[str, Any], change_summary: dict[str, Any], errors: list[str], warnings: list[str]) -> None:
    path = "change_summary.rollout_wedge"
    wedge = change_summary.get("rollout_wedge")
    if wedge is None:
        change_proposal = payload.get("change_proposal")
        if isinstance(change_proposal, dict) and isinstance(change_proposal.get("rollout_wedge"), dict):
            wedge = change_proposal.get("rollout_wedge")
            warnings.append("legacy field path change_proposal.rollout_wedge detected; migrate to change_summary.rollout_wedge")

    if not isinstance(wedge, dict):
        errors.append(f"{path} must be an object")
        return

    stages = _require_list(wedge.get("wedge_stages"), f"{path}.wedge_stages", errors, min_items=2)
    prev_target = -1.0
    first_target: float | None = None
    for idx, stage in enumerate(stages):
        prefix = f"{path}.wedge_stages[{idx}]"
        if not isinstance(stage, dict):
            errors.append(f"{prefix} must be an object")
            continue

        for required_field in WEDGE_STAGE_FIELDS:
            if required_field not in stage:
                errors.append(f"{prefix}.{required_field} is required")

        _require_non_empty_str(stage.get("stage_id"), f"{prefix}.stage_id", errors)

        target = stage.get("target_percentage")
        if not _is_number(target) or not (0 <= float(target) <= 100):
            errors.append(f"{prefix}.target_percentage must be numeric in range 0..100")
        else:
            target_f = float(target)
            if target_f <= prev_target:
                errors.append(f"{prefix}.target_percentage must be strictly increasing across stages")
            prev_target = target_f
            if first_target is None:
                first_target = target_f

        duration = stage.get("duration_hours")
        if not _is_number(duration) or float(duration) <= 0:
            errors.append(f"{prefix}.duration_hours must be numeric > 0")

        criteria = _require_list(stage.get("success_criteria"), f"{prefix}.success_criteria", errors, min_items=1)
        for i, condition in enumerate(criteria):
            if not isinstance(condition, str) or not condition.strip():
                errors.append(f"{prefix}.success_criteria[{i}] must be a non-empty string")

        _require_non_empty_str(stage.get("rollback_trigger"), f"{prefix}.rollback_trigger", errors)

    initial = wedge.get("initial_percentage")
    if not _is_number(initial) or not (0 < float(initial) <= 100):
        errors.append(f"{path}.initial_percentage must be numeric in range (0,100]")
    elif first_target is not None and float(initial) > first_target:
        errors.append(f"{path}.initial_percentage must be <= first stage target_percentage")

    increment = _require_non_empty_str(wedge.get("increment_policy"), f"{path}.increment_policy", errors)
    if increment and increment not in INCREMENT_POLICIES:
        errors.append(f"{path}.increment_policy must be one of: {', '.join(sorted(INCREMENT_POLICIES))}")

    blast = wedge.get("max_blast_radius")
    if not _is_number(blast) or not (0 < float(blast) <= 100):
        errors.append(f"{path}.max_blast_radius must be numeric in range (0,100]")
    elif first_target is not None and float(blast) < first_target:
        errors.append(f"{path}.max_blast_radius must be >= first stage target_percentage")

    observation = wedge.get("observation_window_hours")
    if not _is_number(observation) or float(observation) < 1:
        errors.append(f"{path}.observation_window_hours must be numeric >= 1")

    wedge_state = _require_non_empty_str(wedge.get("wedge_state"), f"{path}.wedge_state", errors)
    if wedge_state and wedge_state not in WEDGE_STATES:
        errors.append(f"{path}.wedge_state must be one of: {', '.join(sorted(WEDGE_STATES))}")


def _validate_rollback_command(change_summary: dict[str, Any], project_root: Path, errors: list[str]) -> None:
    path = "change_summary.rollback_command"
    rollback = change_summary.get("rollback_command")
    if not isinstance(rollback, dict):
        errors.append(f"{path} must be an object")
        return

    command = _require_non_empty_str(rollback.get("command"), f"{path}.command", errors)
    if command:
        if "\n" in command or "\r" in command:
            errors.append(f"{path}.command must be single-line")
        if _contains_placeholder(command):
            errors.append(f"{path}.command contains unresolved placeholders")

    idempotent = rollback.get("idempotent")
    if not isinstance(idempotent, bool) or idempotent is not True:
        errors.append(f"{path}.idempotent must be true")

    tested_in_ci = rollback.get("tested_in_ci")
    if not isinstance(tested_in_ci, bool) or tested_in_ci is not True:
        errors.append(f"{path}.tested_in_ci must be true")

    evidence_path = _require_non_empty_str(rollback.get("test_evidence_artifact"), f"{path}.test_evidence_artifact", errors)
    if evidence_path:
        _validate_artifact_path(
            artifact_path=evidence_path,
            field=f"{path}.test_evidence_artifact",
            project_root=project_root,
            errors=errors,
            required_prefix="artifacts/",
        )

    scope = rollback.get("rollback_scope")
    if not isinstance(scope, dict):
        errors.append(f"{path}.rollback_scope must be an object")
    else:
        reverts = _require_list(scope.get("reverts"), f"{path}.rollback_scope.reverts", errors, min_items=1)
        for idx, item in enumerate(reverts):
            if not isinstance(item, str) or not item.strip():
                errors.append(f"{path}.rollback_scope.reverts[{idx}] must be a non-empty string")

        excludes = _require_list(scope.get("does_not_revert"), f"{path}.rollback_scope.does_not_revert", errors, min_items=1)
        for idx, item in enumerate(excludes):
            if not isinstance(item, str) or not item.strip():
                errors.append(f"{path}.rollback_scope.does_not_revert[{idx}] must be a non-empty string")

    duration = _require_non_empty_str(rollback.get("estimated_duration"), f"{path}.estimated_duration", errors)
    if duration and not _valid_duration(duration):
        errors.append(f"{path}.estimated_duration must use compact format (e.g. 30s, 2m, 1h30m)")


def _validate_benchmark_correctness(change_summary: dict[str, Any], project_root: Path, errors: list[str]) -> None:
    path = "change_summary.benchmark_and_correctness_artifacts"
    bc = change_summary.get("benchmark_and_correctness_artifacts")
    if not isinstance(bc, dict):
        errors.append(f"{path} must be an object")
        return

    metrics = _require_list(bc.get("benchmark_metrics"), f"{path}.benchmark_metrics", errors, min_items=1)
    for idx, metric in enumerate(metrics):
        prefix = f"{path}.benchmark_metrics[{idx}]"
        if not isinstance(metric, dict):
            errors.append(f"{prefix} must be an object")
            continue
        _require_non_empty_str(metric.get("metric_name"), f"{prefix}.metric_name", errors)
        _require_non_empty_str(metric.get("unit"), f"{prefix}.unit", errors)

        measured = metric.get("measured_value")
        baseline = metric.get("baseline_value")
        delta = metric.get("delta")
        if not _is_number(measured):
            errors.append(f"{prefix}.measured_value must be numeric")
        if not _is_number(baseline):
            errors.append(f"{prefix}.baseline_value must be numeric")
        if not _is_number(delta):
            errors.append(f"{prefix}.delta must be numeric")

        if _is_number(measured) and _is_number(baseline) and _is_number(delta):
            expected_delta = float(measured) - float(baseline)
            if abs(float(delta) - expected_delta) > DELTA_EPSILON:
                errors.append(f"{prefix}.delta must equal measured_value - baseline_value")

        if not isinstance(metric.get("within_acceptable_bounds"), bool):
            errors.append(f"{prefix}.within_acceptable_bounds must be boolean")

        artifact_path = _require_non_empty_str(metric.get("artifact_path"), f"{prefix}.artifact_path", errors)
        if artifact_path:
            _validate_artifact_path(
                artifact_path=artifact_path,
                field=f"{prefix}.artifact_path",
                project_root=project_root,
                errors=errors,
                required_prefix="artifacts/section_",
            )

    suites = _require_list(bc.get("correctness_suites"), f"{path}.correctness_suites", errors, min_items=1)
    for idx, suite in enumerate(suites):
        prefix = f"{path}.correctness_suites[{idx}]"
        if not isinstance(suite, dict):
            errors.append(f"{prefix} must be an object")
            continue

        _require_non_empty_str(suite.get("suite_name"), f"{prefix}.suite_name", errors)
        pass_count = suite.get("pass_count")
        fail_count = suite.get("fail_count")
        if not isinstance(pass_count, int) or isinstance(pass_count, bool) or pass_count < 0:
            errors.append(f"{prefix}.pass_count must be an integer >= 0")
        if not isinstance(fail_count, int) or isinstance(fail_count, bool) or fail_count < 0:
            errors.append(f"{prefix}.fail_count must be an integer >= 0")
        if isinstance(pass_count, int) and isinstance(fail_count, int) and pass_count + fail_count == 0:
            errors.append(f"{prefix} must report at least one test result")

        coverage = suite.get("coverage_percent")
        if not _is_number(coverage) or not (0 <= float(coverage) <= 100):
            errors.append(f"{prefix}.coverage_percent must be numeric in range 0..100")

        raw_output = _require_non_empty_str(suite.get("raw_output_artifact"), f"{prefix}.raw_output_artifact", errors)
        if raw_output:
            _validate_artifact_path(
                artifact_path=raw_output,
                field=f"{prefix}.raw_output_artifact",
                project_root=project_root,
                errors=errors,
                required_prefix="artifacts/section_",
            )


def _validate_summary_file(summary_path: Path, project_root: Path) -> tuple[bool, dict[str, Any]]:
    errors: list[str] = []
    warnings: list[str] = []
    events: list[dict[str, Any]] = []

    summary_rel = _rel(summary_path, project_root)
    if not summary_path.is_file():
        message = f"summary file listed in diff but missing on disk: {summary_rel}"
        trace = _trace_id({"summary_file": summary_rel, "error": message})
        return False, {
            "summary_file": summary_rel,
            "ok": False,
            "errors": [message],
            "warnings": [],
            "events": [
                {
                    "event_code": "CONTRACT_NO_MERGE_INCOMPLETE",
                    "severity": "error",
                    "trace_correlation": trace,
                    "summary_file": summary_rel,
                    "message": message,
                }
            ],
        }

    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        message = f"invalid JSON in {summary_rel}: {exc}"
        trace = _trace_id({"summary_file": summary_rel, "error": str(exc)})
        return False, {
            "summary_file": summary_rel,
            "ok": False,
            "errors": [message],
            "warnings": [],
            "events": [
                {
                    "event_code": "CONTRACT_NO_MERGE_INCOMPLETE",
                    "severity": "error",
                    "trace_correlation": trace,
                    "summary_file": summary_rel,
                    "message": message,
                }
            ],
        }

    if not isinstance(payload, dict):
        message = f"{summary_rel} must contain a JSON object"
        trace = _trace_id({"summary_file": summary_rel, "error": message})
        return False, {
            "summary_file": summary_rel,
            "ok": False,
            "errors": [message],
            "warnings": [],
            "events": [
                {
                    "event_code": "CONTRACT_NO_MERGE_INCOMPLETE",
                    "severity": "error",
                    "trace_correlation": trace,
                    "summary_file": summary_rel,
                    "message": message,
                }
            ],
        }

    trace = _trace_id(payload)

    change_summary = payload.get("change_summary")
    if not isinstance(change_summary, dict):
        errors.append("change_summary must be an object")
        change_summary = {}

    _validate_base_fields(change_summary, errors)
    _validate_compat_threat(change_summary, project_root, errors)
    _validate_ev_score(change_summary, project_root, errors)
    _validate_expected_loss(change_summary, errors)
    _validate_fallback_trigger(change_summary, errors)
    _validate_rollout_wedge(payload, change_summary, errors, warnings)
    _validate_rollback_command(change_summary, project_root, errors)
    _validate_benchmark_correctness(change_summary, project_root, errors)

    ok = len(errors) == 0
    event_code = "CONTRACT_NO_MERGE_VALIDATED" if ok else "CONTRACT_NO_MERGE_INCOMPLETE"
    message = (
        f"no-contract-no-merge contract validated: {summary_rel}"
        if ok
        else f"no-contract-no-merge contract incomplete: {summary_rel}"
    )
    events.append(
        {
            "event_code": event_code,
            "severity": "info" if ok else "error",
            "trace_correlation": trace,
            "summary_file": summary_rel,
            "message": message,
        }
    )

    return ok, {
        "summary_file": summary_rel,
        "ok": ok,
        "trace_correlation": trace,
        "errors": errors,
        "warnings": warnings,
        "events": events,
    }


def run_checks(
    *,
    changed_files: list[str] | None = None,
    changed_files_path: Path | None = None,
    labels: set[str] | None = None,
    override_label: str = "contract-override",
    project_root: Path = ROOT,
    summary_dir: Path | None = None,
) -> tuple[bool, dict[str, Any]]:
    summary_dir = summary_dir or (project_root / "docs" / "change_summaries")
    template_path = project_root / "docs" / "templates" / "change_summary_template.md"
    example_path = project_root / "docs" / "change_summaries" / "example_change_summary.json"

    labels = labels or set()

    errors: list[str] = []
    warnings: list[str] = []
    events: list[dict[str, Any]] = []

    if not template_path.is_file():
        errors.append(f"missing template file: {_rel(template_path, project_root)}")
    if not example_path.is_file():
        errors.append(f"missing example change summary: {_rel(example_path, project_root)}")
    if not summary_dir.exists():
        errors.append(f"missing summary directory: {_rel(summary_dir, project_root)}")

    if changed_files is None:
        if changed_files_path is not None:
            changed_files = _load_changed_files(changed_files_path)
            changed_source = _rel(changed_files_path, project_root)
        else:
            changed_files = _discover_changed_files_from_git(project_root)
            changed_source = "git-diff"
    else:
        changed_source = "inline"

    normalized_changed = sorted({_norm(path) for path in changed_files if path})
    changed_subsystem_files = [path for path in normalized_changed if _is_subsystem_path(path)]
    requires_contract = len(changed_subsystem_files) > 0

    summary_dir_rel = _rel(summary_dir, project_root)
    changed_summary_files = [
        path
        for path in normalized_changed
        if path.startswith(f"{summary_dir_rel}/") and path.endswith(".json")
    ]

    validated_summaries: list[dict[str, Any]] = []

    if requires_contract and not changed_summary_files:
        message = (
            "missing required change summary file under "
            f"{summary_dir_rel}/ for subsystem code changes"
        )
        trace = _trace_id({"changed_subsystem_files": changed_subsystem_files})
        errors.append(message)
        events.append(
            {
                "event_code": "CONTRACT_NO_MERGE_MISSING",
                "severity": "error",
                "trace_correlation": trace,
                "message": message,
                "changed_subsystem_files": changed_subsystem_files,
            }
        )

    for summary_rel in changed_summary_files:
        ok, detail = _validate_summary_file(project_root / summary_rel, project_root)
        validated_summaries.append(detail)
        events.extend(detail["events"])
        warnings.extend(detail["warnings"])
        if not ok:
            errors.extend(detail["errors"])

    override_label_present = override_label in labels
    override_applied = False

    if len(errors) > 0 and override_label_present:
        override_applied = True
        warnings.append(
            f"override label `{override_label}` present; allowing merge despite {len(errors)} validation error(s)"
        )
        events.append(
            {
                "event_code": "CONTRACT_NO_MERGE_OVERRIDE",
                "severity": "warning",
                "trace_correlation": _trace_id({"override_label": override_label, "error_count": len(errors)}),
                "message": f"override label `{override_label}` applied",
                "error_count": len(errors),
            }
        )

    ok = len(errors) == 0 or override_applied
    report = {
        "bead_id": "bd-2ut3",
        "ok": ok,
        "changed_files_source": changed_source,
        "changed_file_count": len(normalized_changed),
        "subsystem_change_count": len(changed_subsystem_files),
        "requires_contract": requires_contract,
        "summary_files_checked": [item["summary_file"] for item in validated_summaries],
        "template": _rel(template_path, project_root),
        "example": _rel(example_path, project_root),
        "summary_directory": _rel(summary_dir, project_root),
        "required_event_codes": sorted(REQUIRED_EVENT_CODES),
        "override_label": override_label,
        "labels": sorted(labels),
        "override_label_present": override_label_present,
        "override_applied": override_applied,
        "errors": sorted(dict.fromkeys(errors)),
        "warnings": sorted(dict.fromkeys(warnings)),
        "events": events,
        "validated_summaries": validated_summaries,
    }
    return ok, report


def _build_valid_summary() -> dict[str, Any]:
    return {
        "summary_id": "chg-self-test",
        "contract_version": "1.0",
        "change_summary": {
            "intent": "Validate no-contract-no-merge gate.",
            "scope": {
                "subsystems": ["franken_node.connector"],
                "modules": ["crates/franken-node/src/connector/mock.rs"],
            },
            "surface_area_delta": {
                "new_apis": [],
                "removed_apis": [],
                "changed_signatures": [],
            },
            "affected_contracts": {
                "beads": ["bd-2ut3"],
                "documents": ["docs/specs/section_11/bd-2ut3_contract.md"],
            },
            "operational_impact": {
                "operator_notes": "No runtime change.",
                "required_actions": ["Run gate checks."],
                "rollout_notes": "Safe to proceed with canary.",
            },
            "risk_delta": {
                "previous_tier": "medium",
                "new_tier": "low",
                "rationale": "Machine-verifiable gate reduces merge risk.",
            },
            "compatibility": {
                "backward_compatibility": "compatible",
                "forward_compatibility": "enables",
                "details": "Adds gate enforcement only.",
            },
            "dependency_changes": {
                "added": [],
                "removed": [],
                "updated": [],
            },
            "compatibility_and_threat_evidence": {
                "compatibility_test_suites": [
                    {
                        "suite_name": "tests/security/mock.rs",
                        "pass_count": 3,
                        "fail_count": 0,
                        "artifact_path": "artifacts/11/mock_compat_report.json",
                    }
                ],
                "regression_risk_assessment": {
                    "risk_level": "medium",
                    "api_families": ["POST /v1/mock"],
                    "notes": "No external behavior changes.",
                },
                "threat_vectors": [
                    {
                        "vector": "privilege_escalation",
                        "mitigation": "Capability checks enforced.",
                    },
                    {
                        "vector": "data_exfiltration",
                        "mitigation": "Sensitive fields redacted.",
                    },
                    {
                        "vector": "denial_of_service",
                        "mitigation": "Retry bounds and timeouts.",
                    },
                ],
            },
            "ev_score_and_tier": {
                "ev_score": 72,
                "tier": "T3",
                "dimension_scores": {
                    "code_review": {
                        "score": 0.8,
                        "evidence_ref": "artifacts/11/mock_compat_report.json",
                        "assessed_at": "2026-02-21T00:00:00Z",
                    },
                    "test_coverage": {
                        "score": 0.7,
                        "evidence_ref": "artifacts/section_11/bd-3l8d/correctness_suite_output.txt",
                        "assessed_at": "2026-02-21T00:00:00Z",
                    },
                    "security_audit": {
                        "score": 0.75,
                        "evidence_ref": "artifacts/11/mock_compat_report.json",
                        "assessed_at": "2026-02-21T00:00:00Z",
                    },
                    "supply_chain": {
                        "score": 0.65,
                        "evidence_ref": "artifacts/section_11/bd-nglx/rollback_command_ci_test.json",
                        "assessed_at": "2026-02-21T00:00:00Z",
                    },
                    "conformance": {
                        "score": 0.7,
                        "evidence_ref": "artifacts/section_11/bd-3l8d/benchmark_metrics.json",
                        "assessed_at": "2026-02-21T00:00:00Z",
                    },
                },
                "rationale": "Tier T3 based on audited controls and conformance.",
            },
            "expected_loss_model": {
                "scenarios": [
                    {
                        "name": "minor rollout regression",
                        "probability": 0.1,
                        "impact_value": 250,
                        "impact_unit": "dollars",
                        "mitigation": "Canary rollback.",
                    },
                    {
                        "name": "compatibility mismatch",
                        "probability": 0.05,
                        "impact_value": 1200,
                        "impact_unit": "dollars",
                        "mitigation": "Lockstep gate.",
                    },
                    {
                        "name": "operator delay",
                        "probability": 0.2,
                        "impact_value": 80,
                        "impact_unit": "dollars",
                        "mitigation": "Escalation runbook.",
                    },
                ],
                "aggregate_expected_loss": 101,
                "confidence_interval": {
                    "lower": 80,
                    "upper": 140,
                    "confidence_level": 0.95,
                },
                "loss_category": "minor",
            },
            "fallback_trigger": {
                "trigger_conditions": ["error_rate > 0.05 over 60s sliding window"],
                "fallback_target_state": "last_known_good_checkpoint",
                "rollback_mechanism": "automatic",
                "max_detection_latency_s": 3,
                "recovery_time_objective_s": 20,
                "subsystem_id": "franken_node.control_plane",
                "rationale": "Bounded blast radius during rollout.",
            },
            "rollout_wedge": {
                "wedge_stages": [
                    {
                        "stage_id": "canary-5",
                        "target_percentage": 5,
                        "duration_hours": 2,
                        "success_criteria": ["error_rate <= 0.02"],
                        "rollback_trigger": "error_rate > 0.05",
                    },
                    {
                        "stage_id": "regional-20",
                        "target_percentage": 20,
                        "duration_hours": 4,
                        "success_criteria": ["no critical alerts"],
                        "rollback_trigger": "critical_alert_count > 0",
                    },
                ],
                "initial_percentage": 5,
                "increment_policy": "manual",
                "max_blast_radius": 25,
                "observation_window_hours": 1,
                "wedge_state": "ACTIVE",
            },
            "rollback_command": {
                "command": "franken-node rollback apply --receipt artifacts/section_11/bd-nglx/rollback_command_ci_test.json --force-safe",
                "idempotent": True,
                "tested_in_ci": True,
                "test_evidence_artifact": "artifacts/section_11/bd-nglx/rollback_command_ci_test.json",
                "rollback_scope": {
                    "reverts": ["policy activation state"],
                    "does_not_revert": ["already-emitted audit logs"],
                },
                "estimated_duration": "45s",
            },
            "benchmark_and_correctness_artifacts": {
                "benchmark_metrics": [
                    {
                        "metric_name": "p95_latency_ms",
                        "unit": "ms",
                        "measured_value": 31.4,
                        "baseline_value": 29.8,
                        "delta": 1.6,
                        "within_acceptable_bounds": True,
                        "artifact_path": "artifacts/section_11/bd-3l8d/benchmark_metrics.json",
                    }
                ],
                "correctness_suites": [
                    {
                        "suite_name": "tests/security/control_epoch_validity.rs",
                        "pass_count": 6,
                        "fail_count": 0,
                        "coverage_percent": 92.1,
                        "raw_output_artifact": "artifacts/section_11/bd-3l8d/correctness_suite_output.txt",
                    }
                ],
            },
        },
    }


def self_test() -> tuple[bool, dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="no-contract-no-merge-selftest-") as tmp:
        root = Path(tmp)
        (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
        (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
        (root / "artifacts" / "11").mkdir(parents=True, exist_ok=True)
        (root / "artifacts" / "section_11" / "bd-nglx").mkdir(parents=True, exist_ok=True)
        (root / "artifacts" / "section_11" / "bd-3l8d").mkdir(parents=True, exist_ok=True)

        (root / "docs" / "templates" / "change_summary_template.md").write_text("# template\n", encoding="utf-8")
        (root / "artifacts" / "11" / "mock_compat_report.json").write_text("{\"ok\": true}\n", encoding="utf-8")
        (root / "artifacts" / "section_11" / "bd-nglx" / "rollback_command_ci_test.json").write_text(
            "{\"ok\": true}\n",
            encoding="utf-8",
        )
        (root / "artifacts" / "section_11" / "bd-3l8d" / "benchmark_metrics.json").write_text(
            "{\"ok\": true}\n",
            encoding="utf-8",
        )
        (root / "artifacts" / "section_11" / "bd-3l8d" / "correctness_suite_output.txt").write_text(
            "ok\n",
            encoding="utf-8",
        )

        valid_summary = _build_valid_summary()
        example_path = root / "docs" / "change_summaries" / "example_change_summary.json"
        example_path.write_text(json.dumps(valid_summary, indent=2), encoding="utf-8")
        pass_path = root / "docs" / "change_summaries" / "self_test_summary.json"
        pass_path.write_text(json.dumps(valid_summary, indent=2), encoding="utf-8")

        pass_changed = [
            "crates/franken-node/src/connector/mock.rs",
            "docs/change_summaries/self_test_summary.json",
        ]
        ok_pass, report_pass = run_checks(changed_files=pass_changed, project_root=root)
        assert ok_pass, f"self_test expected pass but failed: {report_pass['errors']}"

        bad_summary = json.loads(json.dumps(valid_summary))
        del bad_summary["change_summary"]["expected_loss_model"]
        bad_path = root / "docs" / "change_summaries" / "broken_summary.json"
        bad_path.write_text(json.dumps(bad_summary, indent=2), encoding="utf-8")
        fail_changed = [
            "crates/franken-node/src/connector/mock.rs",
            "docs/change_summaries/broken_summary.json",
        ]
        ok_fail, report_fail = run_checks(changed_files=fail_changed, project_root=root)
        assert not ok_fail, "self_test expected failure for missing expected_loss_model"
        assert any("expected_loss_model" in err for err in report_fail["errors"])

        ok_override, report_override = run_checks(
            changed_files=fail_changed,
            labels={"contract-override"},
            override_label="contract-override",
            project_root=root,
        )
        assert ok_override, "self_test expected override to force pass"
        assert report_override["override_applied"], "self_test expected override_applied=true"

        ok_missing, report_missing = run_checks(
            changed_files=["crates/franken-node/src/connector/mock.rs"],
            project_root=root,
        )
        assert not ok_missing, "self_test expected failure when summary file is missing"
        assert any("missing required change summary file" in err for err in report_missing["errors"])

    return True, {"ok": True, "self_test": "passed"}


def main() -> int:
    logger = configure_test_logging("check_no_contract_no_merge")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--changed-files",
        default=None,
        help="Path to newline-delimited changed-file list (recommended in CI).",
    )
    parser.add_argument(
        "--project-root",
        default=str(ROOT),
        help="Project root path.",
    )
    parser.add_argument(
        "--labels",
        default="",
        help="Comma-delimited PR labels for override handling.",
    )
    parser.add_argument(
        "--override-label",
        default="contract-override",
        help="Label name that allows audited override.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-test.")
    args = parser.parse_args()

    labels = {label.strip() for label in args.labels.split(",") if label.strip()}

    try:
        if args.self_test:
            ok, payload = self_test()
        else:
            changed_files_path = Path(args.changed_files) if args.changed_files else None
            ok, payload = run_checks(
                changed_files_path=changed_files_path,
                labels=labels,
                override_label=args.override_label,
                project_root=Path(args.project_root),
            )
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        payload = {"ok": False, "error": str(exc)}
        ok = False

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        if ok:
            print("PASS")
        else:
            print("FAIL")
            for err in payload.get("errors", [payload.get("error", "unknown error")]):
                print(f"- {err}")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
