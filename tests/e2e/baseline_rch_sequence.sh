#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/section_bootstrap/bd-2a3"
LOG_JSONL="${OUT_DIR}/rch_command_log.jsonl"
RESULTS_JSON="${OUT_DIR}/baseline_checks.json"
SUMMARY_MD="${OUT_DIR}/baseline_checks.md"
TRACE_ID="trace-bd-2a3-rch"

mkdir -p "${OUT_DIR}"
: > "${LOG_JSONL}"

if ! command -v rch >/dev/null 2>&1; then
  echo "ERROR: rch is required for bd-2a3 baseline checks" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required for bd-2a3 baseline checks" >&2
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

check_class_code() {
  local check_id="$1"
  case "${check_id}" in
    cargo_fmt_check)
      echo "BD2A3-FMT"
      ;;
    cargo_check_all_targets)
      echo "BD2A3-CHECK"
      ;;
    cargo_clippy_all_targets)
      echo "BD2A3-CLIPPY"
      ;;
    *)
      echo "BD2A3-UNKNOWN"
      ;;
  esac
}

run_rch() {
  local check_id="$1"
  local command_str="$2"
  local output_file="${OUT_DIR}/${check_id}.log"
  local start_ns end_ns elapsed_ms exit_code status excerpt class_code status_code
  class_code="$(check_class_code "${check_id}")"

  start_ns="$(date +%s%N)"
  log_event "RCH-BASELINE-010" "info" "Starting ${check_id}: ${command_str}"

  set +e
  (cd "${ROOT_DIR}" && eval "rch exec -- ${command_str}") > "${output_file}" 2>&1
  exit_code=$?
  set -e

  end_ns="$(date +%s%N)"
  elapsed_ms="$(( (end_ns - start_ns) / 1000000 ))"

  if [ "${exit_code}" -eq 0 ]; then
    status="pass"
    status_code="${class_code}-PASS"
    excerpt=""
    log_event "RCH-BASELINE-011" "pass" "${check_id} completed successfully (${elapsed_ms} ms) [${status_code}]"
  else
    status="fail"
    status_code="${class_code}-FAIL"
    excerpt="$(rg -a -n -m 8 "error\\[|error:|failed|failure|panic|warning:" "${output_file}" || true)"
    excerpt="${excerpt:-see full log}"
    log_event "RCH-BASELINE-011" "fail" "${check_id} failed with exit=${exit_code} (${elapsed_ms} ms) [${status_code}]"
  fi

  jq -cn \
    --arg check_id "${check_id}" \
    --arg class_code "${class_code}" \
    --arg status_code "${status_code}" \
    --arg command "${command_str}" \
    --arg status "${status}" \
    --arg output_log "$(realpath --relative-to="${ROOT_DIR}" "${output_file}")" \
    --arg excerpt "${excerpt}" \
    --argjson exit_code "${exit_code}" \
    --argjson elapsed_ms "${elapsed_ms}" \
    '{check_id: $check_id, class_code: $class_code, status_code: $status_code, command: $command, status: $status, exit_code: $exit_code, elapsed_ms: $elapsed_ms, output_log: $output_log, excerpt: $excerpt}'
}

log_event "RCH-BASELINE-001" "info" "Starting rch offloaded baseline sequence."

doctor_log="${OUT_DIR}/rch_doctor.log"
set +e
(cd "${ROOT_DIR}" && rch doctor) > "${doctor_log}" 2>&1
doctor_exit=$?
set -e
if [ "${doctor_exit}" -eq 0 ]; then
  log_event "RCH-BASELINE-002" "pass" "rch doctor passed"
else
  log_event "RCH-BASELINE-003" "warn" "rch doctor failed (continuing): exit=${doctor_exit}"
fi

check_fmt="$(run_rch "cargo_fmt_check" "cargo fmt --check")"
check_check="$(run_rch "cargo_check_all_targets" "cargo check --all-targets")"
check_clippy="$(run_rch "cargo_clippy_all_targets" "cargo clippy --all-targets -- -D warnings")"

checks_json="$(jq -cn \
  --argjson a "${check_fmt}" \
  --argjson b "${check_check}" \
  --argjson c "${check_clippy}" \
  '[$a, $b, $c]')"

passed_count="$(jq '[.[] | select(.status == "pass")] | length' <<< "${checks_json}")"
failed_count="$(jq '[.[] | select(.status == "fail")] | length' <<< "${checks_json}")"
total_count="$(jq 'length' <<< "${checks_json}")"

if [ "${failed_count}" -eq 0 ]; then
  verdict="PASS"
else
  verdict="FAIL"
fi

jq -n \
  --arg bead_id "bd-2a3" \
  --arg trace_id "${TRACE_ID}" \
  --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg verdict "${verdict}" \
  --arg rch_doctor_log "$(realpath --relative-to="${ROOT_DIR}" "${doctor_log}")" \
  --arg log_path "$(realpath --relative-to="${ROOT_DIR}" "${LOG_JSONL}")" \
  --argjson doctor_exit "${doctor_exit}" \
  --argjson checks "${checks_json}" \
  --argjson checks_total "${total_count}" \
  --argjson checks_passed "${passed_count}" \
  --argjson checks_failed "${failed_count}" \
  '{
    bead_id: $bead_id,
    trace_id: $trace_id,
    generated_at: $generated_at,
    verdict: $verdict,
    rch_doctor_exit_code: $doctor_exit,
    rch_doctor_log: $rch_doctor_log,
    command_log: $log_path,
    checks_total: $checks_total,
    checks_passed: $checks_passed,
    checks_failed: $checks_failed,
    checks: $checks
  }' > "${RESULTS_JSON}"

{
  echo "# bd-2a3 Baseline Checks (rch offload)"
  echo
  echo "- Trace ID: \`${TRACE_ID}\`"
  echo "- Verdict: **${verdict}**"
  echo "- rch doctor exit code: \`${doctor_exit}\`"
  echo "- Command log: \`$(realpath --relative-to="${ROOT_DIR}" "${LOG_JSONL}")\`"
  echo
  echo "| Check | Code | Command | Status | Exit | Duration (ms) | Log |"
  echo "|---|---|---|---|---|---:|---|"
  jq -r '.checks[] | "| \(.check_id) | `\(.status_code)` | `\(.command)` | \(.status) | \(.exit_code) | \(.elapsed_ms) | `\(.output_log)` |"' "${RESULTS_JSON}"
  echo
  if [ "${failed_count}" -gt 0 ]; then
    echo "## Failure Excerpts"
    jq -r '.checks[] | select(.status == "fail") | "- **\(.check_id)**: \(.excerpt)"' "${RESULTS_JSON}"
  fi
} > "${SUMMARY_MD}"

if [ "${verdict}" = "PASS" ]; then
  log_event "RCH-BASELINE-099" "info" "Baseline sequence completed with PASS."
else
  log_event "RCH-BASELINE-099" "warn" "Baseline sequence completed with FAIL."
fi

echo "bd-2a3 baseline sequence: ${verdict} (${passed_count}/${total_count} checks passed)"
[ "${verdict}" = "PASS" ]
