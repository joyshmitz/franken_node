#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESULTS_FILE="${ROOT_DIR}/artifacts/15/migration_cohort_results.json"
LOG_FILE="${ROOT_DIR}/artifacts/15/migration_cohort_validation_log.jsonl"
SUMMARY_FILE="${ROOT_DIR}/artifacts/15/migration_cohort_validation_summary.json"
TRACE_ID="trace-bd-sxt5-e2e"

mkdir -p "$(dirname "${RESULTS_FILE}")"
: > "${LOG_FILE}"

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required to run migration_cohort_validation.sh" >&2
  exit 2
fi

log_event() {
  local code="$1"
  local status="$2"
  local detail="$3"
  jq -cn \
    --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg trace_id "${TRACE_ID}" \
    --arg event_code "${code}" \
    --arg status "${status}" \
    --arg detail "${detail}" \
    '{ts: $ts, trace_id: $trace_id, event_code: $event_code, status: $status, detail: $detail}' \
    >> "${LOG_FILE}"
}

check_passed=0
check_failed=0
declare -a failed_checks=()

run_check() {
  local name="$1"
  local jq_expr="$2"
  local detail="$3"

  if jq -e "${jq_expr}" "${RESULTS_FILE}" >/dev/null; then
    check_passed=$((check_passed + 1))
    log_event "MCV-002" "pass" "${name}: ${detail}"
  else
    check_failed=$((check_failed + 1))
    failed_checks+=("${name}")
    log_event "MCV-003" "fail" "${name}: ${detail}"
  fi
}

log_event "MCV-001" "info" "Starting deterministic migration cohort validation."

if [ ! -f "${RESULTS_FILE}" ]; then
  log_event "MCV-003" "fail" "Missing required artifact: ${RESULTS_FILE}"
  jq -n \
    --arg bead_id "bd-sxt5" \
    --arg verdict "FAIL" \
    --arg error "missing_results_file" \
    --arg results_file "${RESULTS_FILE}" \
    --arg log_file "${LOG_FILE}" \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    '{
      bead_id: $bead_id,
      verdict: $verdict,
      error: $error,
      results_file: $results_file,
      log_file: $log_file,
      generated_at: $timestamp
    }' > "${SUMMARY_FILE}"
  exit 1
fi

run_check \
  "cohort_size_gte_10" \
  '.projects | length >= 10' \
  "cohort has at least 10 projects"

run_check \
  "required_archetypes_present" \
  '([.projects[].archetype] | unique) as $covered
   | ["web-server-express","ssr-nextjs","cli-tool","library-package","worker-bun","monorepo","native-addon","typescript-heavy","test-heavy","minimal"]
   | map($covered | index(.) != null)
   | all' \
  "required archetype coverage is complete"

run_check \
  "baseline_results_complete" \
  '.projects
   | all(
       .baseline.total_tests > 0
       and (.baseline.passed + .baseline.failed == .baseline.total_tests)
       and (.baseline.status == "pass")
     )' \
  "every project has complete baseline test evidence"

run_check \
  "migration_artifacts_present" \
  '.projects
   | all(
       (.migration.audit_report | length) > 0
       and (.migration.rewrite_report | length) > 0
       and (.migration.lockstep_report | length) > 0
       and (.migration.rollback_artifact | length) > 0
     )' \
  "every project includes audit/rewrite/lockstep/rollback artifacts"

run_check \
  "post_validation_deterministic" \
  '.projects
   | all(
       .repeated_runs.runs >= 3
       and .repeated_runs.identical_outcomes_runs == .repeated_runs.runs
       and .repeated_runs.flaky_rate_pct < 1
     )' \
  "repeated validation runs are deterministic (flaky rate < 1%)"

run_check \
  "per_project_success_rule" \
  '.projects
   | all(
       (.post_migration.pass_rate_pct >= 95)
       or ((.post_migration.known_incompatibilities | length) > 0)
     )' \
  "each project either reaches >=95% pass or documents known incompatibilities"

run_check \
  "cohort_success_rate_rule" \
  '.aggregate.cohort_success_rate_pct >= 80
   and .aggregate.projects_meeting_success_criteria >= ((.projects | length) * 0.8)' \
  "cohort-wide success rate is at least 80%"

run_check \
  "aggregate_consistency" \
  '.aggregate.cohort_size == (.projects | length)
   and .aggregate.projects_meeting_success_criteria
       == ([.projects[] | select(.success_criteria_met == true)] | length)' \
  "aggregate counters match project-level data"

run_check \
  "version_pinning_complete" \
  '.projects | all((.pinned_ref.repo | length) > 0 and (.pinned_ref.commit | length) > 0)' \
  "each cohort project is pinned to a repo+commit"

run_check \
  "ci_reproducibility_flags" \
  '.aggregate.ci_reproducible == true and .aggregate.determinism_verified == true' \
  "artifact explicitly marks deterministic and CI-reproducible outcomes"

verdict="PASS"
if [ "${check_failed}" -gt 0 ]; then
  verdict="FAIL"
fi

if [ "${#failed_checks[@]}" -eq 0 ]; then
  failed_checks_json='[]'
else
  failed_checks_json="$(printf '%s\n' "${failed_checks[@]}" | jq -R . | jq -s .)"
fi

jq -n \
  --arg bead_id "bd-sxt5" \
  --arg trace_id "${TRACE_ID}" \
  --arg verdict "${verdict}" \
  --arg results_file "${RESULTS_FILE}" \
  --arg log_file "${LOG_FILE}" \
  --arg summary_file "${SUMMARY_FILE}" \
  --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --argjson checks_passed "${check_passed}" \
  --argjson checks_failed "${check_failed}" \
  --argjson checks_total "$((check_passed + check_failed))" \
  --argjson failed_checks "${failed_checks_json}" \
  '{
    bead_id: $bead_id,
    trace_id: $trace_id,
    verdict: $verdict,
    checks_passed: $checks_passed,
    checks_failed: $checks_failed,
    checks_total: $checks_total,
    failed_checks: $failed_checks,
    results_file: $results_file,
    log_file: $log_file,
    generated_at: $timestamp
  }' > "${SUMMARY_FILE}"

log_event "MCV-004" "info" "Completed validation with verdict=${verdict}."

echo "migration cohort validation: ${verdict} (${check_passed}/$((check_passed + check_failed)) checks)"
[ "${verdict}" = "PASS" ]
