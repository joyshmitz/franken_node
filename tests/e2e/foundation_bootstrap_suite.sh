#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/section_bootstrap/bd-3k9t"
STAGES_DIR="${OUT_DIR}/stage_outputs"
LOG_JSONL="${OUT_DIR}/foundation_e2e_log.jsonl"
STAGE_RESULTS_JSONL="${OUT_DIR}/stage_results.jsonl"
SUMMARY_JSON="${OUT_DIR}/foundation_e2e_summary.json"
BUNDLE_JSON="${OUT_DIR}/foundation_e2e_bundle.json"
SUMMARY_MD="${OUT_DIR}/foundation_e2e_summary.md"
TRACE_ID="${TRACE_ID:-trace-bd-3k9t-foundation-e2e}"

mkdir -p "${OUT_DIR}" "${STAGES_DIR}"
: > "${LOG_JSONL}"
: > "${STAGE_RESULTS_JSONL}"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required" >&2
  exit 2
fi

log_event() {
  local event_code="$1"
  local stage="$2"
  local category="$3"
  local status="$4"
  local detail="$5"
  local command="$6"
  local exit_code="${7:-}"

  jq -cn \
    --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg trace_id "${TRACE_ID}" \
    --arg event_code "${event_code}" \
    --arg stage "${stage}" \
    --arg category "${category}" \
    --arg status "${status}" \
    --arg detail "${detail}" \
    --arg command "${command}" \
    --arg exit_code "${exit_code}" \
    '{
      ts: $ts,
      trace_id: $trace_id,
      event_code: $event_code,
      stage: $stage,
      category: $category,
      status: $status,
      detail: $detail,
      command: $command,
      exit_code: (if $exit_code == "" then null else ($exit_code | tonumber) end)
    }' >> "${LOG_JSONL}"
}

record_stage_result() {
  local stage_id="$1"
  local category="$2"
  local command="$3"
  local expected_exit="$4"
  local expected_pattern="$5"
  local actual_exit="$6"
  local pattern_matched="$7"
  local status="$8"
  local stdout_path="$9"
  local stderr_path="${10}"

  jq -cn \
    --arg stage_id "${stage_id}" \
    --arg category "${category}" \
    --arg command "${command}" \
    --arg expected_exit "${expected_exit}" \
    --arg expected_pattern "${expected_pattern}" \
    --arg actual_exit "${actual_exit}" \
    --arg pattern_matched "${pattern_matched}" \
    --arg status "${status}" \
    --arg stdout_path "${stdout_path}" \
    --arg stderr_path "${stderr_path}" \
    '{
      stage_id: $stage_id,
      category: $category,
      command: $command,
      expected_exit: ($expected_exit | tonumber),
      expected_pattern: (if $expected_pattern == "" then null else $expected_pattern end),
      actual_exit: ($actual_exit | tonumber),
      pattern_matched: ($pattern_matched == "true"),
      status: $status,
      stdout_path: $stdout_path,
      stderr_path: $stderr_path
    }' >> "${STAGE_RESULTS_JSONL}"
}

run_stage() {
  local stage_id="$1"
  local category="$2"
  local expected_exit="$3"
  local expected_pattern="$4"
  local command="$5"

  local stdout_path="${STAGES_DIR}/${stage_id}.stdout"
  local stderr_path="${STAGES_DIR}/${stage_id}.stderr"

  log_event "FB-E2E-010" "${stage_id}" "${category}" "start" "stage start" "${command}" ""

  set +e
  bash -lc "cd '${ROOT_DIR}' && ${command}" >"${stdout_path}" 2>"${stderr_path}"
  local actual_exit=$?
  set -e

  local pattern_matched="true"
  if [ -n "${expected_pattern}" ]; then
    if grep -Eq "${expected_pattern}" "${stderr_path}" || grep -Eq "${expected_pattern}" "${stdout_path}"; then
      pattern_matched="true"
    else
      pattern_matched="false"
    fi
  fi

  local status="fail"
  if [ "${actual_exit}" -eq "${expected_exit}" ] && [ "${pattern_matched}" = "true" ]; then
    status="pass"
  fi

  record_stage_result \
    "${stage_id}" \
    "${category}" \
    "${command}" \
    "${expected_exit}" \
    "${expected_pattern}" \
    "${actual_exit}" \
    "${pattern_matched}" \
    "${status}" \
    "${stdout_path#${ROOT_DIR}/}" \
    "${stderr_path#${ROOT_DIR}/}"

  local detail="expected_exit=${expected_exit} actual_exit=${actual_exit} pattern_matched=${pattern_matched}"
  log_event "FB-E2E-020" "${stage_id}" "${category}" "${status}" "${detail}" "${command}" "${actual_exit}"
}

log_event "FB-E2E-001" "suite" "suite" "start" "Starting foundation bootstrap E2E suite" "tests/e2e/foundation_bootstrap_suite.sh" ""

run_stage \
  "run_surface_contract" \
  "clean" \
  "0" \
  "" \
  "python3 -c \"from pathlib import Path; s=Path('crates/franken-node/src/cli.rs').read_text(encoding='utf-8'); raise SystemExit(0 if 'Run(RunArgs)' in s else 1)\""

run_stage \
  "config_profile_resolution" \
  "clean" \
  "0" \
  "" \
  "tests/e2e/config_profile_resolution.sh"

run_stage \
  "init_profile_bootstrap" \
  "clean" \
  "0" \
  "" \
  "tests/e2e/init_profile_bootstrap.sh"

run_stage \
  "doctor_command_diagnostics" \
  "clean" \
  "0" \
  "" \
  "tests/e2e/doctor_command_diagnostics.sh"

run_stage \
  "transplant_verify_missing_snapshot" \
  "degraded" \
  "2" \
  "Snapshot directory not found" \
  "transplant/verify_lockfile.sh --json"

run_stage \
  "transplant_drift_probe_missing_snapshot" \
  "drifted" \
  "2" \
  "Not found:" \
  "transplant/drift_detect.sh --json"

python3 - <<'PY' "${ROOT_DIR}" "${STAGE_RESULTS_JSONL}" "${SUMMARY_JSON}" "${BUNDLE_JSON}" "${SUMMARY_MD}" "${TRACE_ID}"
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
stage_results_path = Path(sys.argv[2])
summary_path = Path(sys.argv[3])
bundle_path = Path(sys.argv[4])
summary_md_path = Path(sys.argv[5])
trace_id = sys.argv[6]

stage_results = []
for line in stage_results_path.read_text(encoding="utf-8").splitlines():
    if line.strip():
        stage_results.append(json.loads(line))

stage_order = [row["stage_id"] for row in stage_results]
required_stage_ids = [
    "run_surface_contract",
    "config_profile_resolution",
    "init_profile_bootstrap",
    "doctor_command_diagnostics",
    "transplant_verify_missing_snapshot",
    "transplant_drift_probe_missing_snapshot",
]
missing_stage_ids = [sid for sid in required_stage_ids if sid not in stage_order]

pass_count = sum(1 for row in stage_results if row["status"] == "pass")
fail_count = len(stage_results) - pass_count
coverage = {
    "clean": sum(1 for row in stage_results if row["category"] == "clean"),
    "degraded": sum(1 for row in stage_results if row["category"] == "degraded"),
    "drifted": sum(1 for row in stage_results if row["category"] == "drifted"),
}

verdict = "PASS"
if fail_count > 0:
    verdict = "FAIL"
if missing_stage_ids:
    verdict = "FAIL"
if not all(coverage[k] >= 1 for k in ("clean", "degraded", "drifted")):
    verdict = "FAIL"

replay_inputs = [
    "artifacts/section_bootstrap/bd-n9r/resolved_config_snapshot.json",
    "artifacts/section_bootstrap/bd-32e/init_snapshots.json",
    "artifacts/section_bootstrap/bd-1pk/doctor_checks_matrix.json",
    "transplant/TRANSPLANT_LOCKFILE.sha256",
    "transplant/transplant_manifest.txt",
]

summary = {
    "bead_id": "bd-3k9t",
    "schema_version": "bootstrap-foundation-e2e-v1",
    "trace_id": trace_id,
    "suite": "foundation_bootstrap_suite",
    "verdict": verdict,
    "stage_count": len(stage_results),
    "pass_count": pass_count,
    "fail_count": fail_count,
    "coverage": coverage,
    "missing_stage_ids": missing_stage_ids,
    "stage_order": stage_order,
    "required_journeys": {
        "run": "run_surface_contract" in stage_order,
        "config": "config_profile_resolution" in stage_order,
        "init": "init_profile_bootstrap" in stage_order,
        "doctor": "doctor_command_diagnostics" in stage_order,
        "transplant_integrity": "transplant_verify_missing_snapshot" in stage_order,
    },
}

bundle = {
    "bead_id": "bd-3k9t",
    "schema_version": "bootstrap-e2e-bundle-v1",
    "trace_id": trace_id,
    "summary": summary,
    "stage_results": stage_results,
    "replay_inputs": replay_inputs,
    "artifacts": {
        "stage_results_jsonl": str(stage_results_path.relative_to(root)),
        "summary_json": str(summary_path.relative_to(root)),
        "log_jsonl": "artifacts/section_bootstrap/bd-3k9t/foundation_e2e_log.jsonl",
    },
}

summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")

lines = [
    "# bd-3k9t Foundation E2E Summary",
    "",
    f"- Verdict: **{verdict}**",
    f"- Stage pass/fail: **{pass_count}/{len(stage_results)}**",
    f"- Coverage: clean={coverage['clean']}, degraded={coverage['degraded']}, drifted={coverage['drifted']}",
    "",
    "| Stage | Category | Status | Expected Exit | Actual Exit |",
    "|---|---|---|---:|---:|",
]
for row in stage_results:
    lines.append(
        f"| {row['stage_id']} | {row['category']} | {row['status']} | {row['expected_exit']} | {row['actual_exit']} |"
    )
lines.extend(
    [
        "",
        "- Log: `artifacts/section_bootstrap/bd-3k9t/foundation_e2e_log.jsonl`",
        "- Summary JSON: `artifacts/section_bootstrap/bd-3k9t/foundation_e2e_summary.json`",
        "- Bundle JSON: `artifacts/section_bootstrap/bd-3k9t/foundation_e2e_bundle.json`",
    ]
)
summary_md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

if verdict != "PASS":
    raise SystemExit(1)
PY

if [ $? -eq 0 ]; then
  log_event "FB-E2E-099" "suite" "suite" "pass" "Foundation bootstrap E2E suite passed" "tests/e2e/foundation_bootstrap_suite.sh" "0"
else
  log_event "FB-E2E-099" "suite" "suite" "fail" "Foundation bootstrap E2E suite failed" "tests/e2e/foundation_bootstrap_suite.sh" "1"
  exit 1
fi

echo "bd-3k9t foundation bootstrap suite: PASS"
