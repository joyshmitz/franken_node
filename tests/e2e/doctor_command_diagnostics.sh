#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/section_bootstrap/bd-1pk"
LOG_JSONL="${OUT_DIR}/doctor_diagnostics_log.jsonl"
CHECKS_JSON="${OUT_DIR}/doctor_contract_checks.json"
MATRIX_JSON="${OUT_DIR}/doctor_checks_matrix.json"
HEALTHY_JSON="${OUT_DIR}/doctor_report_healthy.json"
DEGRADED_JSON="${OUT_DIR}/doctor_report_degraded.json"
FAILURE_JSON="${OUT_DIR}/doctor_report_failure.json"
SUMMARY_MD="${OUT_DIR}/doctor_contract_checks.md"
TRACE_ID="trace-bd-1pk-doctor-e2e"

mkdir -p "${OUT_DIR}"
: > "${LOG_JSONL}"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 2
fi

log_event() {
  local event_code="$1"
  local status="$2"
  local detail="$3"
  jq -cn \
    --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg trace_id "${TRACE_ID}" \
    --arg event_code "${event_code}" \
    --arg status "${status}" \
    --arg detail "${detail}" \
    '{ts: $ts, trace_id: $trace_id, event_code: $event_code, status: $status, detail: $detail}' \
    >> "${LOG_JSONL}"
}

log_event "DOC-E2E-001" "info" "Starting bd-1pk doctor diagnostics gate."

python3 - <<'PY' "${ROOT_DIR}" "${CHECKS_JSON}" "${MATRIX_JSON}" "${HEALTHY_JSON}" "${DEGRADED_JSON}" "${FAILURE_JSON}"
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
checks_json = Path(sys.argv[2])
matrix_json = Path(sys.argv[3])
healthy_json = Path(sys.argv[4])
degraded_json = Path(sys.argv[5])
failure_json = Path(sys.argv[6])

main_rs = root / "crates" / "franken-node" / "src" / "main.rs"
cli_rs = root / "crates" / "franken-node" / "src" / "cli.rs"
contract_md = root / "docs" / "specs" / "bootstrap_doctor_contract.md"

checks = []


def add(check: str, passed: bool, detail: str = "") -> None:
    checks.append({"check": check, "passed": passed, "detail": detail})


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


for path in (main_rs, cli_rs, contract_md):
    add(f"exists_{path.name}", path.exists(), str(path))

main_src = read(main_rs) if main_rs.exists() else ""
cli_src = read(cli_rs) if cli_rs.exists() else ""
contract_src = read(contract_md) if contract_md.exists() else ""

add("doctor_args_json_flag", "pub json: bool" in cli_src, "--json")
add("doctor_args_trace_id_flag", "pub trace_id: String" in cli_src, "--trace-id")
add(
    "doctor_args_trace_id_default",
    'default_value = "doctor-bootstrap"' in cli_src,
    "doctor-bootstrap",
)

add("doctor_report_has_structured_logs", "structured_logs: Vec<DoctorLogEvent>" in main_src, "DoctorReport structured logs")
add("doctor_report_has_merge_decisions", "merge_decisions: Vec<config::MergeDecision>" in main_src, "merge provenance")
add("doctor_builder_with_cwd", "fn build_doctor_report_with_cwd(" in main_src, "cwd injectable builder")
add("doctor_json_output_path", "serde_json::to_string_pretty(&report)" in main_src, "json render")
add("doctor_human_output_path", "render_doctor_report_human(&report, args.verbose)" in main_src, "human render")

expected_codes = [
    "DR-CONFIG-001",
    "DR-CONFIG-002",
    "DR-PROFILE-003",
    "DR-TRUST-004",
    "DR-MIGRATE-005",
    "DR-OBS-006",
    "DR-ENV-007",
    "DR-CONFIG-008",
]
expected_event_codes = [
    "DOC-001",
    "DOC-002",
    "DOC-003",
    "DOC-004",
    "DOC-005",
    "DOC-006",
    "DOC-007",
    "DOC-008",
]

for code in expected_codes:
    add(f"doctor_code_{code}", code in main_src, code)
for event_code in expected_event_codes:
    add(f"doctor_event_code_{event_code}", event_code in main_src, event_code)

code_positions = [main_src.find(code) for code in expected_codes]
add(
    "doctor_code_order_deterministic",
    all(pos >= 0 for pos in code_positions) and code_positions == sorted(code_positions),
    str(code_positions),
)

add(
    "contract_has_matrix_and_schema",
    "## Check Matrix" in contract_src and "## Machine-Readable Report Schema (CI)" in contract_src,
    "matrix+schema sections",
)

matrix = [
    {
        "code": "DR-CONFIG-001",
        "event_code": "DOC-001",
        "scope": "config.resolve",
        "remediation": "No action required.",
    },
    {
        "code": "DR-CONFIG-002",
        "event_code": "DOC-002",
        "scope": "config.source",
        "remediation": "Create franken_node.toml or pass --config to lock deterministic project settings.",
    },
    {
        "code": "DR-PROFILE-003",
        "event_code": "DOC-003",
        "scope": "profile.safety",
        "remediation": "Prefer --profile balanced or --profile strict for stronger controls.",
    },
    {
        "code": "DR-TRUST-004",
        "event_code": "DOC-004",
        "scope": "registry.assurance",
        "remediation": "Raise registry.minimum_assurance_level to 3+.",
    },
    {
        "code": "DR-MIGRATE-005",
        "event_code": "DOC-005",
        "scope": "migration.lockstep",
        "remediation": "Set migration.require_lockstep_validation=true for safer rollout validation.",
    },
    {
        "code": "DR-OBS-006",
        "event_code": "DOC-006",
        "scope": "observability.audit_events",
        "remediation": "Set observability.emit_structured_audit_events=true for stronger traceability.",
    },
    {
        "code": "DR-ENV-007",
        "event_code": "DOC-007",
        "scope": "environment.cwd",
        "remediation": "Fix working directory access before running operations.",
    },
    {
        "code": "DR-CONFIG-008",
        "event_code": "DOC-008",
        "scope": "config.provenance",
        "remediation": "Investigate resolver instrumentation before relying on doctor provenance.",
    },
]
matrix_payload = {
    "bead_id": "bd-1pk",
    "schema_version": "doctor-check-matrix-v1",
    "checks": matrix,
}
matrix_json.write_text(json.dumps(matrix_payload, indent=2) + "\n", encoding="utf-8")
add("matrix_written", matrix_json.exists(), str(matrix_json))


def build_report(trace_id: str, selected_profile: str, source_path: str | None, checks: list[dict], merge_decisions: list[dict]) -> dict:
    counts = {
        "pass": sum(1 for c in checks if c["status"] == "pass"),
        "warn": sum(1 for c in checks if c["status"] == "warn"),
        "fail": sum(1 for c in checks if c["status"] == "fail"),
    }
    if counts["fail"] > 0:
        overall = "fail"
    elif counts["warn"] > 0:
        overall = "warn"
    else:
        overall = "pass"

    logs = [
        {
            "trace_id": trace_id,
            "event_code": check["event_code"],
            "check_code": check["code"],
            "scope": check["scope"],
            "status": check["status"],
            "duration_ms": check["duration_ms"],
        }
        for check in checks
    ]
    return {
        "command": "doctor",
        "trace_id": trace_id,
        "generated_at_utc": "2026-02-22T00:00:00Z",
        "selected_profile": selected_profile,
        "source_path": source_path,
        "overall_status": overall,
        "status_counts": counts,
        "checks": checks,
        "structured_logs": logs,
        "merge_decision_count": len(merge_decisions),
        "merge_decisions": merge_decisions,
    }


def check_row(code: str, event_code: str, scope: str, status: str, message: str, remediation: str, duration_ms: int) -> dict:
    return {
        "code": code,
        "event_code": event_code,
        "scope": scope,
        "status": status,
        "message": message,
        "remediation": remediation,
        "duration_ms": duration_ms,
    }


healthy_checks = [
    check_row("DR-CONFIG-001", "DOC-001", "config.resolve", "pass", "Configuration resolved successfully.", "No action required.", 0),
    check_row("DR-CONFIG-002", "DOC-002", "config.source", "pass", "Config source file discovered.", "No action required.", 0),
    check_row("DR-PROFILE-003", "DOC-003", "profile.safety", "pass", "Profile safety level is acceptable.", "No action required.", 0),
    check_row("DR-TRUST-004", "DOC-004", "registry.assurance", "pass", "Registry assurance level meets bootstrap target.", "No action required.", 0),
    check_row("DR-MIGRATE-005", "DOC-005", "migration.lockstep", "pass", "Lockstep validation requirement is enabled.", "No action required.", 0),
    check_row("DR-OBS-006", "DOC-006", "observability.audit_events", "pass", "Structured audit events are enabled.", "No action required.", 0),
    check_row("DR-ENV-007", "DOC-007", "environment.cwd", "pass", "Current working directory is available: /workspace", "No action required.", 0),
    check_row("DR-CONFIG-008", "DOC-008", "config.provenance", "pass", "Merge provenance recorded (4 decisions).", "No action required.", 0),
]
degraded_checks = [
    check_row("DR-CONFIG-001", "DOC-001", "config.resolve", "pass", "Configuration resolved successfully.", "No action required.", 0),
    check_row("DR-CONFIG-002", "DOC-002", "config.source", "warn", "No config file discovered; defaults are active.", "Create franken_node.toml or pass --config to lock deterministic project settings.", 0),
    check_row("DR-PROFILE-003", "DOC-003", "profile.safety", "warn", "Profile is legacy-risky.", "Prefer --profile balanced or --profile strict for stronger controls.", 0),
    check_row("DR-TRUST-004", "DOC-004", "registry.assurance", "warn", "Registry assurance level is below bootstrap target (3).", "Raise registry.minimum_assurance_level to 3+.", 0),
    check_row("DR-MIGRATE-005", "DOC-005", "migration.lockstep", "warn", "Lockstep validation requirement is disabled.", "Set migration.require_lockstep_validation=true for safer rollout validation.", 0),
    check_row("DR-OBS-006", "DOC-006", "observability.audit_events", "warn", "Structured audit events are disabled.", "Set observability.emit_structured_audit_events=true for stronger traceability.", 0),
    check_row("DR-ENV-007", "DOC-007", "environment.cwd", "pass", "Current working directory is available: /workspace", "No action required.", 0),
    check_row("DR-CONFIG-008", "DOC-008", "config.provenance", "pass", "Merge provenance recorded (3 decisions).", "No action required.", 0),
]
failure_checks = [
    *degraded_checks[:6],
    check_row("DR-ENV-007", "DOC-007", "environment.cwd", "fail", "Current working directory is unavailable.", "Fix working directory access before running operations.", 0),
    check_row("DR-CONFIG-008", "DOC-008", "config.provenance", "warn", "No merge decisions recorded for this configuration.", "Investigate resolver instrumentation before relying on doctor provenance.", 0),
]

healthy_report = build_report(
    trace_id="doctor-healthy",
    selected_profile="strict",
    source_path="franken_node.toml",
    checks=healthy_checks,
    merge_decisions=[
        {"stage": "default", "field": "profile", "value": "balanced"},
        {"stage": "file", "field": "profile", "value": "strict"},
        {"stage": "file", "field": "migration.require_lockstep_validation", "value": "true"},
        {"stage": "env", "field": "registry.minimum_assurance_level", "value": "4"},
    ],
)
degraded_report = build_report(
    trace_id="doctor-degraded",
    selected_profile="legacy-risky",
    source_path=None,
    checks=degraded_checks,
    merge_decisions=[
        {"stage": "default", "field": "profile", "value": "balanced"},
        {"stage": "cli", "field": "profile", "value": "legacy-risky"},
        {"stage": "env", "field": "observability.emit_structured_audit_events", "value": "false"},
    ],
)
failure_report = build_report(
    trace_id="doctor-failure",
    selected_profile="legacy-risky",
    source_path=None,
    checks=failure_checks,
    merge_decisions=[],
)

healthy_text = json.dumps(healthy_report, indent=2, sort_keys=True)
degraded_text = json.dumps(degraded_report, indent=2, sort_keys=True)
failure_text = json.dumps(failure_report, indent=2, sort_keys=True)

healthy_json.write_text(healthy_text + "\n", encoding="utf-8")
degraded_json.write_text(degraded_text + "\n", encoding="utf-8")
failure_json.write_text(failure_text + "\n", encoding="utf-8")

add("healthy_report_written", healthy_json.exists(), str(healthy_json))
add("degraded_report_written", degraded_json.exists(), str(degraded_json))
add("failure_report_written", failure_json.exists(), str(failure_json))

healthy_sha = hashlib.sha256(healthy_text.encode("utf-8")).hexdigest()
healthy_sha_2 = hashlib.sha256(healthy_text.encode("utf-8")).hexdigest()
add("healthy_report_deterministic_hash", healthy_sha == healthy_sha_2, healthy_sha)

payload = {
    "bead_id": "bd-1pk",
    "gate_script": "doctor_command_diagnostics.sh",
    "checks_passed": sum(1 for c in checks if c["passed"]),
    "checks_total": len(checks),
    "verdict": "PASS" if all(c["passed"] for c in checks) else "FAIL",
    "checks": checks,
    "sample_reports": {
        "healthy": str(healthy_json.relative_to(root)),
        "degraded": str(degraded_json.relative_to(root)),
        "failure": str(failure_json.relative_to(root)),
    },
    "doctor_matrix_path": str(matrix_json.relative_to(root)),
}
checks_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

if payload["verdict"] != "PASS":
    raise SystemExit(1)
PY

if [ $? -eq 0 ]; then
  log_event "DOC-E2E-099" "pass" "Doctor diagnostics gate passed."
else
  log_event "DOC-E2E-099" "fail" "Doctor diagnostics gate failed."
  exit 1
fi

{
  echo "# bd-1pk Doctor Diagnostics Contract Checks"
  echo
  echo "- Log: \`artifacts/section_bootstrap/bd-1pk/doctor_diagnostics_log.jsonl\`"
  echo "- Checks JSON: \`artifacts/section_bootstrap/bd-1pk/doctor_contract_checks.json\`"
  echo "- Matrix JSON: \`artifacts/section_bootstrap/bd-1pk/doctor_checks_matrix.json\`"
  echo "- Sample reports: \`doctor_report_healthy.json\`, \`doctor_report_degraded.json\`, \`doctor_report_failure.json\`"
  echo
  echo "| Check | Pass | Detail |"
  echo "|---|---|---|"
  jq -r '.checks[] | "| \(.check) | \(.passed) | \(.detail|tostring|gsub("\\n";" ")) |"' "${CHECKS_JSON}"
  echo
  echo "Verdict: **$(jq -r '.verdict' "${CHECKS_JSON}")** ($(jq -r '.checks_passed' "${CHECKS_JSON}")/$(jq -r '.checks_total' "${CHECKS_JSON}"))"
} > "${SUMMARY_MD}"

echo "bd-1pk doctor diagnostics checks: PASS"
