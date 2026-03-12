#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/replacement_gap/bd-1z5a"
STAGES_DIR="${OUT_DIR}/stage_outputs"
LOG_JSONL="${OUT_DIR}/operator_e2e_log.jsonl"
SUMMARY_JSON="${OUT_DIR}/operator_e2e_summary.json"
BUNDLE_JSON="${OUT_DIR}/operator_e2e_bundle.json"
SUMMARY_MD="${OUT_DIR}/operator_e2e_summary.md"
STAGE_RESULTS_JSONL="${STAGES_DIR}/stage_results.jsonl"
TRACE_ID="${TRACE_ID:-trace-bd-1z5a-operator-e2e-final}"
SUITE_TARGET_DIR="${SUITE_TARGET_DIR:-/tmp/rch_franken_node_bd1z5a3_suite}"

mkdir -p "${OUT_DIR}" "${STAGES_DIR}"
: > "${LOG_JSONL}"
: > "${STAGE_RESULTS_JSONL}"

if ! command -v rch >/dev/null 2>&1; then
  echo "ERROR: rch is required for bd-1z5a operator E2E checks" >&2
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required for bd-1z5a operator E2E checks" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required for bd-1z5a operator E2E checks" >&2
  exit 2
fi

hash_string() {
  python3 - "$1" <<'PY'
import hashlib
import sys

print(hashlib.sha256(sys.argv[1].encode("utf-8")).hexdigest())
PY
}

extract_build_id() {
  python3 - "$1" "$2" <<'PY'
import pathlib
import re
import sys

pattern = re.compile(r"\b\d{12,20}\b")
for path_str in sys.argv[1:]:
    path = pathlib.Path(path_str)
    if not path.exists():
        continue
    text = path.read_text(encoding="utf-8", errors="ignore")
    matches = pattern.findall(text)
    if matches:
        print(matches[0])
        raise SystemExit(0)
raise SystemExit(1)
PY
}

extract_rch_outcome() {
  python3 - "$1" "$2" <<'PY'
import pathlib
import re
import sys

pattern = re.compile(r"\[RCH\]\s+(remote|local)\b")
last_match = None
for path_str in sys.argv[1:]:
    path = pathlib.Path(path_str)
    if not path.exists():
        continue
    text = path.read_text(encoding="utf-8", errors="ignore")
    for match in pattern.finditer(text):
        last_match = match.group(1)
if last_match is None:
    raise SystemExit(1)
print(last_match)
PY
}

lookup_recent_build_metadata() {
  python3 - "$1" "$2" "$3" <<'PY'
import datetime as dt
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

command = sys.argv[1]
expected_exit = int(sys.argv[2])
started_epoch = int(sys.argv[3])

started_cutoff = dt.datetime.fromtimestamp(max(started_epoch - 30, 0), tz=dt.timezone.utc)


def parse_ts(raw: object) -> dt.datetime | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def emit(row: dict[str, object]) -> None:
    print(json.dumps(row, sort_keys=True))
    raise SystemExit(0)


try:
    proc = subprocess.run(
        ["rch", "status", "--jobs", "--json"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    payload = json.loads(proc.stdout)
except Exception:
    payload = {}

recent_builds = payload.get("data", {}).get("recent_builds")
if isinstance(recent_builds, list):
    candidates: list[tuple[dt.datetime, dict[str, object]]] = []
    for row in recent_builds:
        if not isinstance(row, dict):
            continue
        if row.get("command") != command:
            continue
        if row.get("exit_code") != expected_exit:
            continue
        if row.get("location") != "remote":
            continue
        build_id = row.get("id")
        if not isinstance(build_id, int) or build_id <= 0:
            continue
        completed_at = parse_ts(row.get("completed_at"))
        if completed_at is None or completed_at < started_cutoff:
            continue
        candidates.append((completed_at, row))
    if candidates:
        candidates.sort(key=lambda item: item[0], reverse=True)
        row = candidates[0][1]
        emit(
            {
                "build_id": row["id"],
                "build_id_kind": "daemon_build_id",
                "worker_id": row.get("worker_id"),
                "started_at": row.get("started_at"),
                "completed_at": row.get("completed_at"),
                "duration_ms": row.get("duration_ms"),
            }
        )

telemetry_db = Path.home() / ".local/share/rch/telemetry/telemetry.db"
if not telemetry_db.is_file():
    raise SystemExit(1)

con = None
try:
    con = sqlite3.connect(str(telemetry_db))
    con.row_factory = sqlite3.Row
    rows = con.execute(
        """
        SELECT
            id,
            worker_id,
            exit_code,
            duration_ms,
            strftime('%Y-%m-%dT%H:%M:%SZ', completed_at, 'unixepoch') AS completed_at
        FROM test_runs
        WHERE command = ?
          AND exit_code = ?
          AND completed_at >= ?
        ORDER BY completed_at DESC
        LIMIT 10
        """,
        (command, expected_exit, max(started_epoch - 30, 0)),
    ).fetchall()
except sqlite3.Error:
    raise SystemExit(1)
finally:
    try:
        con.close()
    except Exception:
        pass

if not rows:
    raise SystemExit(1)

row = rows[0]
emit(
    {
        "build_id": row["id"],
        "build_id_kind": "telemetry_test_run_id",
        "worker_id": row["worker_id"],
        "completed_at": row["completed_at"],
        "duration_ms": row["duration_ms"],
    }
)
PY
}

detect_test_count() {
  python3 - "$1" "$2" <<'PY'
import pathlib
import re
import sys

pattern = re.compile(r"running (\d+) tests")
for path_str in sys.argv[1:]:
    path = pathlib.Path(path_str)
    if not path.exists():
        continue
    text = path.read_text(encoding="utf-8", errors="ignore")
    match = pattern.search(text)
    if match:
        print(match.group(1))
        raise SystemExit(0)
raise SystemExit(1)
PY
}

log_event() {
  local event_code="$1"
  local stage_id="$2"
  local status="$3"
  local capsule_id="$4"
  local verifier_id="$5"
  local claim_id="$6"
  local commitment_digest="$7"
  local decision="$8"
  local reason_code="$9"
  local fraud_proof_id="${10}"
  local command="${11}"
  local detail="${12}"
  local exit_code="${13:-}"
  local build_id="${14:-}"
  local build_id_kind="${15:-}"
  local worker_id="${16:-}"
  local completed_at="${17:-}"
  local duration_ms="${18:-}"
  local rch_outcome="${19:-}"

  jq -cn \
    --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg trace_id "${TRACE_ID}" \
    --arg event_code "${event_code}" \
    --arg stage_id "${stage_id}" \
    --arg status "${status}" \
    --arg capsule_id "${capsule_id}" \
    --arg verifier_id "${verifier_id}" \
    --arg claim_id "${claim_id}" \
    --arg commitment_digest "${commitment_digest}" \
    --arg decision "${decision}" \
    --arg reason_code "${reason_code}" \
    --arg fraud_proof_id "${fraud_proof_id}" \
    --arg command "${command}" \
    --arg detail "${detail}" \
    --arg exit_code "${exit_code}" \
    --arg build_id "${build_id}" \
    --arg build_id_kind "${build_id_kind}" \
    --arg worker_id "${worker_id}" \
    --arg completed_at "${completed_at}" \
    --arg duration_ms "${duration_ms}" \
    --arg rch_outcome "${rch_outcome}" \
    '{
      ts: $ts,
      trace_id: $trace_id,
      event_code: $event_code,
      stage_id: $stage_id,
      status: $status,
      capsule_id: $capsule_id,
      verifier_id: $verifier_id,
      claim_id: $claim_id,
      commitment_digest: $commitment_digest,
      decision: $decision,
      reason_code: $reason_code,
      fraud_proof_id: $fraud_proof_id,
      command: $command,
      detail: $detail,
      exit_code: (if $exit_code == "" then null else ($exit_code | tonumber) end),
      build_id: (if $build_id == "" then null else ($build_id | tonumber) end),
      build_id_kind: (if $build_id_kind == "" then null else $build_id_kind end),
      worker_id: (if $worker_id == "" then null else $worker_id end),
      completed_at: (if $completed_at == "" then null else $completed_at end),
      duration_ms: (if $duration_ms == "" then null else ($duration_ms | tonumber) end),
      rch_outcome: (if $rch_outcome == "" then null else $rch_outcome end)
    }' >> "${LOG_JSONL}"
}

record_stage_result() {
  local stage_id="$1"
  local event_code="$2"
  local command="$3"
  local status="$4"
  local exit_code="$5"
  local build_id="$6"
  local capsule_id="$7"
  local verifier_id="$8"
  local claim_id="$9"
  local commitment_digest="${10}"
  local decision="${11}"
  local reason_code="${12}"
  local fraud_proof_id="${13}"
  local stdout_path="${14}"
  local stderr_path="${15}"
  local build_id_kind="${16:-}"
  local worker_id="${17:-}"
  local completed_at="${18:-}"
  local duration_ms="${19:-}"
  local rch_outcome="${20:-}"

  jq -cn \
    --arg stage_id "${stage_id}" \
    --arg event_code "${event_code}" \
    --arg command "${command}" \
    --arg status "${status}" \
    --arg exit_code "${exit_code}" \
    --arg build_id "${build_id}" \
    --arg capsule_id "${capsule_id}" \
    --arg verifier_id "${verifier_id}" \
    --arg claim_id "${claim_id}" \
    --arg commitment_digest "${commitment_digest}" \
    --arg decision "${decision}" \
    --arg reason_code "${reason_code}" \
    --arg fraud_proof_id "${fraud_proof_id}" \
    --arg stdout_path "${stdout_path}" \
    --arg stderr_path "${stderr_path}" \
    --arg build_id_kind "${build_id_kind}" \
    --arg worker_id "${worker_id}" \
    --arg completed_at "${completed_at}" \
    --arg duration_ms "${duration_ms}" \
    --arg rch_outcome "${rch_outcome}" \
    '{
      stage_id: $stage_id,
      event_code: $event_code,
      command: $command,
      status: $status,
      exit_code: ($exit_code | tonumber),
      build_id: (if $build_id == "" then null else ($build_id | tonumber) end),
      capsule_id: $capsule_id,
      verifier_id: $verifier_id,
      claim_id: $claim_id,
      commitment_digest: $commitment_digest,
      decision: $decision,
      reason_code: $reason_code,
      fraud_proof_id: $fraud_proof_id,
      build_id_kind: (if $build_id_kind == "" then null else $build_id_kind end),
      worker_id: (if $worker_id == "" then null else $worker_id end),
      completed_at: (if $completed_at == "" then null else $completed_at end),
      duration_ms: (if $duration_ms == "" then null else ($duration_ms | tonumber) end),
      rch_outcome: (if $rch_outcome == "" then null else $rch_outcome end),
      stdout_path: $stdout_path,
      stderr_path: $stderr_path
    }' >> "${STAGE_RESULTS_JSONL}"
}

run_stage() {
  local stage_id="$1"
  local event_code="$2"
  local capsule_id="$3"
  local verifier_id="$4"
  local claim_id="$5"
  local decision="$6"
  local reason_code="$7"
  local fraud_proof_id="$8"
  local command="$9"

  local stdout_path="${STAGES_DIR}/${stage_id}.stdout"
  local stderr_path="${STAGES_DIR}/${stage_id}.stderr"
  local commitment_digest
  local status
  local exit_code
  local build_id=""
  local build_id_kind=""
  local build_metadata=""
  local worker_id=""
  local completed_at=""
  local duration_ms=""
  local detail
  local rch_outcome="unknown"
  local test_count=""
  local zero_tests="false"
  local effective_command
  local stage_started_epoch

  commitment_digest="$(hash_string "${stage_id}|${capsule_id}|${verifier_id}|${claim_id}|${decision}|${reason_code}|${command}")"
  effective_command="env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${SUITE_TARGET_DIR} ${command}"
  stage_started_epoch="$(date -u +%s)"

  log_event \
    "${event_code%_*}_STARTED" \
    "${stage_id}" \
    "start" \
    "${capsule_id}" \
    "${verifier_id}" \
    "${claim_id}" \
    "${commitment_digest}" \
    "${decision}" \
    "${reason_code}" \
    "${fraud_proof_id}" \
    "${effective_command}" \
    "stage start"

  set +e
  bash -lc "cd '${ROOT_DIR}' && env RCH_VISIBILITY=summary rch exec -- ${effective_command}" >"${stdout_path}" 2>"${stderr_path}"
  exit_code=$?
  set -e

  if extract_rch_outcome "${stdout_path}" "${stderr_path}" >/tmp/bd_1z5a_3_rch_outcome.$$ 2>/dev/null; then
    rch_outcome="$(cat /tmp/bd_1z5a_3_rch_outcome.$$)"
    rm -f /tmp/bd_1z5a_3_rch_outcome.$$
  fi
  if extract_build_id "${stdout_path}" "${stderr_path}" >/tmp/bd_1z5a_3_build_id.$$ 2>/dev/null; then
    build_id="$(cat /tmp/bd_1z5a_3_build_id.$$)"
    rm -f /tmp/bd_1z5a_3_build_id.$$
  fi
  if [ -z "${build_id_kind}" ] || [ -z "${worker_id}" ] || [ -z "${completed_at}" ] || [ -z "${duration_ms}" ]; then
    if build_metadata="$(lookup_recent_build_metadata "${effective_command}" "${exit_code}" "${stage_started_epoch}" 2>/dev/null)"; then
      if [ -z "${build_id}" ]; then
        build_id="$(printf '%s' "${build_metadata}" | jq -r '.build_id // empty')"
      fi
      build_id_kind="$(printf '%s' "${build_metadata}" | jq -r '.build_id_kind // empty')"
      worker_id="$(printf '%s' "${build_metadata}" | jq -r '.worker_id // empty')"
      completed_at="$(printf '%s' "${build_metadata}" | jq -r '.completed_at // empty')"
      duration_ms="$(printf '%s' "${build_metadata}" | jq -r '.duration_ms // empty')"
    fi
  fi

  if [ "${exit_code}" -eq 0 ]; then
    status="pass"
  else
    status="fail"
  fi

  if detect_test_count "${stdout_path}" "${stderr_path}" >/tmp/bd_1z5a_3_test_count.$$ 2>/dev/null; then
    test_count="$(cat /tmp/bd_1z5a_3_test_count.$$)"
    rm -f /tmp/bd_1z5a_3_test_count.$$
    if [ "${test_count}" = "0" ]; then
      zero_tests="true"
      status="fail"
    fi
  fi

  detail="exit=${exit_code} rch=${rch_outcome}"
  if [ -n "${build_id}" ]; then
    detail="${detail} build_id=${build_id}"
  fi
  if [ -n "${build_id_kind}" ]; then
    detail="${detail} build_kind=${build_id_kind}"
  fi
  if [ -n "${worker_id}" ]; then
    detail="${detail} worker=${worker_id}"
  fi
  if [ -n "${duration_ms}" ]; then
    detail="${detail} duration_ms=${duration_ms}"
  fi
  if [ -n "${test_count}" ]; then
    detail="${detail} tests=${test_count}"
  fi
  if [ "${zero_tests}" = "true" ]; then
    detail="${detail} zero-tests-filtered"
  fi
  if [ "${rch_outcome}" != "remote" ]; then
    status="fail"
    if [ "${rch_outcome}" = "local" ]; then
      detail="${detail} rch-local-fallback"
    else
      detail="${detail} rch-outcome-missing"
    fi
  fi
  if [ "${exit_code}" -eq 0 ] && [ -z "${build_id}" ]; then
    status="fail"
    detail="${detail} missing-build-id"
  fi

  log_event \
    "${event_code}" \
    "${stage_id}" \
    "${status}" \
    "${capsule_id}" \
    "${verifier_id}" \
    "${claim_id}" \
    "${commitment_digest}" \
    "${decision}" \
    "${reason_code}" \
    "${fraud_proof_id}" \
    "${effective_command}" \
    "${detail}" \
    "${exit_code}" \
    "${build_id}" \
    "${build_id_kind}" \
    "${worker_id}" \
    "${completed_at}" \
    "${duration_ms}" \
    "${rch_outcome}"

  record_stage_result \
    "${stage_id}" \
    "${event_code}" \
    "${effective_command}" \
    "${status}" \
    "${exit_code}" \
    "${build_id}" \
    "${capsule_id}" \
    "${verifier_id}" \
    "${claim_id}" \
    "${commitment_digest}" \
    "${decision}" \
    "${reason_code}" \
    "${fraud_proof_id}" \
    "${stdout_path#${ROOT_DIR}/}" \
    "${stderr_path#${ROOT_DIR}/}" \
    "${build_id_kind}" \
    "${worker_id}" \
    "${completed_at}" \
    "${duration_ms}" \
    "${rch_outcome}"
}

log_event \
  "CAPSULE_VERIFY_SUITE_START" \
  "suite" \
  "start" \
  "suite-bd-1z5a" \
  "operator-e2e" \
  "bd-1z5a" \
  "$(hash_string "suite-start|${TRACE_ID}")" \
  "observe" \
  "SUITE_START" \
  "" \
  "tests/e2e/verifier_replay_operator_suite.sh" \
  "starting bd-1z5a operator E2E suite"

run_stage \
  "capsule_verify_success" \
  "CAPSULE_VERIFY_PASSED" \
  "capsule-claim-ref-001" \
  "v1" \
  "claim-ref-001" \
  "allow" \
  "CAPSULE_REPLAY_MATCH" \
  "" \
  "cargo test -p frankenengine-node --features extended-surfaces test_replay_capsule_match --lib -- --nocapture"

run_stage \
  "capsule_verify_reject_tampered" \
  "CAPSULE_VERIFY_REJECTED" \
  "cap-005" \
  "ver-0001" \
  "att-005" \
  "deny" \
  "ERR_VEP_INVALID_CAPSULE" \
  "fraud-proof-cap-005" \
  "cargo test -p frankenengine-node --features extended-surfaces test_register_replay_capsule_rejects_tampered_integrity_hash --lib -- --nocapture"

run_stage \
  "capsule_verify_fraud_proof" \
  "CAPSULE_VERIFY_FRAUD_PROOF_EXTRACTED" \
  "verification-regression-capsule" \
  "pipeline-verifier" \
  "verification_regression" \
  "deny" \
  "ERR_PIPE_VALIDATION_FAILURE" \
  "counterexample-witness-verification_regression" \
  "cargo test -p frankenengine-node test_verification_emits_counterexample_witness_for_failure --lib -- --nocapture"

run_stage \
  "capsule_verify_quarantine_replay" \
  "CAPSULE_VERIFY_QUARANTINE_REPLAYED" \
  "decision-DEC-003" \
  "policy-v1" \
  "DEC-003" \
  "quarantine" \
  "QUARANTINE_REPRODUCED" \
  "" \
  "cargo test -p frankenengine-node test_verify_quarantine_reproduced --lib -- --nocapture"

run_stage \
  "verifier_score_update" \
  "VERIFIER_SCORE_UPDATED" \
  "scoreboard-snapshot-v1" \
  "vef-claim-engine" \
  "trust-integrity" \
  "score_update" \
  "EVT_SCOREBOARD_UPDATED" \
  "" \
  "cargo test -p frankenengine-node test_events_contain_scoreboard_updated --lib -- --nocapture"

python3 - <<'PY' "${ROOT_DIR}" "${STAGE_RESULTS_JSONL}" "${LOG_JSONL}" "${SUMMARY_JSON}" "${BUNDLE_JSON}" "${SUMMARY_MD}" "${TRACE_ID}"
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
stage_results_path = Path(sys.argv[2])
log_jsonl_path = Path(sys.argv[3])
summary_path = Path(sys.argv[4])
bundle_path = Path(sys.argv[5])
summary_md_path = Path(sys.argv[6])
trace_id = sys.argv[7]

required_stage_ids = [
    "capsule_verify_success",
    "capsule_verify_reject_tampered",
    "capsule_verify_fraud_proof",
    "capsule_verify_quarantine_replay",
    "verifier_score_update",
]
required_event_codes = [
    "CAPSULE_VERIFY_PASSED",
    "CAPSULE_VERIFY_REJECTED",
    "CAPSULE_VERIFY_FRAUD_PROOF_EXTRACTED",
    "CAPSULE_VERIFY_QUARANTINE_REPLAYED",
    "VERIFIER_SCORE_UPDATED",
]

stage_results = []
for line in stage_results_path.read_text(encoding="utf-8").splitlines():
    if line.strip():
        stage_results.append(json.loads(line))

logs = []
for line in log_jsonl_path.read_text(encoding="utf-8").splitlines():
    if line.strip():
        logs.append(json.loads(line))

stage_ids = [row["stage_id"] for row in stage_results]
missing_stage_ids = [stage_id for stage_id in required_stage_ids if stage_id not in stage_ids]
pass_count = sum(1 for row in stage_results if row["status"] == "pass")
fail_count = len(stage_results) - pass_count
stage_build_ids = [row["build_id"] for row in stage_results if isinstance(row.get("build_id"), int) and row["build_id"] > 0]
stage_build_id_kinds = [
    next(
        (
            row.get("build_id_kind")
            for row in stage_results
            if row.get("stage_id") == stage_id and isinstance(row.get("build_id_kind"), str)
        ),
        None,
    )
    for stage_id in required_stage_ids
]
missing_build_stage_ids = [
    row["stage_id"]
    for row in stage_results
    if row["stage_id"] in required_stage_ids
    and not (isinstance(row.get("build_id"), int) and row["build_id"] > 0)
]
non_remote_stage_ids = [
    row["stage_id"]
    for row in stage_results
    if row["stage_id"] in required_stage_ids and row.get("rch_outcome") != "remote"
]
missing_provenance_stage_ids = [
    row["stage_id"]
    for row in stage_results
    if row["stage_id"] in required_stage_ids
    and (
        not isinstance(row.get("build_id_kind"), str)
        or not row["build_id_kind"]
        or not isinstance(row.get("worker_id"), str)
        or not row["worker_id"]
        or not isinstance(row.get("completed_at"), str)
        or not row["completed_at"]
        or not isinstance(row.get("duration_ms"), int)
        or row["duration_ms"] <= 0
    )
]

event_codes = {row["event_code"] for row in logs}
missing_event_codes = [code for code in required_event_codes if code not in event_codes]
trace_ids = sorted({row.get("trace_id", "") for row in logs})
for row in logs:
    if row.get("stage_id") == "suite":
        continue
    for stage_result in stage_results:
        if stage_result.get("stage_id") == row.get("stage_id"):
            row["build_id"] = stage_result.get("build_id")
            row["build_id_kind"] = stage_result.get("build_id_kind")
            row["worker_id"] = stage_result.get("worker_id")
            row["completed_at"] = stage_result.get("completed_at")
            row["duration_ms"] = stage_result.get("duration_ms")
            row["rch_outcome"] = stage_result.get("rch_outcome")
            break
log_jsonl_path.write_text(
    "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in logs),
    encoding="utf-8",
)

verdict = "PASS"
if (
    fail_count > 0
    or missing_stage_ids
    or missing_event_codes
    or len(trace_ids) != 1
    or missing_build_stage_ids
    or non_remote_stage_ids
    or missing_provenance_stage_ids
):
    verdict = "FAIL"

summary = {
    "schema_version": "replacement-gap-operator-e2e-v1",
    "bead_id": "bd-1z5a.3",
    "parent_bead": "bd-1z5a",
    "trace_id": trace_id,
    "suite": "verifier_replay_operator_suite",
    "verdict": verdict,
    "stage_count": len(stage_results),
    "pass_count": pass_count,
    "fail_count": fail_count,
    "required_stage_ids": required_stage_ids,
    "missing_stage_ids": missing_stage_ids,
    "required_event_codes": required_event_codes,
    "missing_event_codes": missing_event_codes,
    "build_ids": stage_build_ids,
    "build_id_kinds": stage_build_id_kinds,
    "missing_build_stage_ids": missing_build_stage_ids,
    "non_remote_stage_ids": non_remote_stage_ids,
    "missing_provenance_stage_ids": missing_provenance_stage_ids,
    "stage_ids": stage_ids,
    "stage_provenance": {
        row["stage_id"]: {
            "build_id": row.get("build_id"),
            "build_id_kind": row.get("build_id_kind"),
            "worker_id": row.get("worker_id"),
            "completed_at": row.get("completed_at"),
            "duration_ms": row.get("duration_ms"),
            "rch_outcome": row.get("rch_outcome"),
        }
        for row in stage_results
        if row.get("stage_id") in required_stage_ids
    },
}

bundle = {
    "schema_version": "replacement-gap-operator-e2e-bundle-v1",
    "bead_id": "bd-1z5a.3",
    "parent_bead": "bd-1z5a",
    "trace_id": trace_id,
    "verdict": verdict,
    "summary_path": str(summary_path.relative_to(root)),
    "structured_log_path": str(log_jsonl_path.relative_to(root)),
    "stage_results": stage_results,
    "replay_inputs": [
        "tests/e2e/verifier_replay_operator_suite.sh",
        "scripts/check_verifier_replay_operator_e2e.py",
        "crates/franken-node/src/connector/verifier_sdk.rs",
        "crates/franken-node/src/verifier_economy/mod.rs",
        "crates/franken-node/src/connector/migration_pipeline.rs",
        "crates/franken-node/src/connector/vef_claim_integration.rs",
        "crates/franken-node/src/connector/control_evidence_replay.rs",
        "tests/conformance/control_evidence_replay.rs",
        "artifacts/10.17/verifier_sdk_certification_report.json",
        "artifacts/10.17/public_trust_scoreboard_snapshot.json",
    ],
}

summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
bundle_path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")

with summary_md_path.open("w", encoding="utf-8") as fh:
    fh.write("# bd-1z5a.3 Operator E2E Summary\n\n")
    fh.write(f"- Trace ID: `{trace_id}`\n")
    fh.write(f"- Verdict: **{verdict}**\n")
    fh.write(f"- Build IDs: `{', '.join(str(build_id) for build_id in stage_build_ids) if stage_build_ids else 'none-detected'}`\n")
    fh.write("- Build ID Kind: `daemon_build_id` when retained by `rch status --jobs`; otherwise persisted `telemetry_test_run_id` from `~/.local/share/rch/telemetry/telemetry.db`\n")
    fh.write("\n")
    fh.write("| Stage | Event | Decision | Reason | Status | Exit | Build ID | Kind | Worker | Completed | Duration ms |\n")
    fh.write("|---|---|---|---|---|---:|---|---|---|---|---:|\n")
    for row in stage_results:
        fh.write(
            "| {stage_id} | `{event_code}` | `{decision}` | `{reason_code}` | {status} | {exit_code} | `{build_id}` | `{build_id_kind}` | `{worker_id}` | `{completed_at}` | {duration_ms} |\n".format(
                stage_id=row["stage_id"],
                event_code=row["event_code"],
                decision=row["decision"],
                reason_code=row["reason_code"],
                status=row["status"],
                exit_code=row["exit_code"],
                build_id=row["build_id"] or "",
                build_id_kind=row.get("build_id_kind") or "",
                worker_id=row.get("worker_id") or "",
                completed_at=row.get("completed_at") or "",
                duration_ms=row.get("duration_ms") or "",
            )
        )
    if missing_stage_ids or missing_event_codes:
        fh.write("\n## Missing Coverage\n")
        if missing_stage_ids:
            fh.write(f"- Missing stages: {', '.join(missing_stage_ids)}\n")
        if missing_event_codes:
            fh.write(f"- Missing event codes: {', '.join(missing_event_codes)}\n")
    if missing_build_stage_ids:
        fh.write("\n## Missing Provenance\n")
        fh.write(f"- Missing build IDs: {', '.join(missing_build_stage_ids)}\n")
    if non_remote_stage_ids:
        fh.write("\n## Non-Remote Outcomes\n")
        fh.write(f"- Stages without confirmed remote execution: {', '.join(non_remote_stage_ids)}\n")
    if missing_provenance_stage_ids:
        fh.write("\n## Incomplete Provenance Fields\n")
        fh.write(f"- Stages missing provenance metadata: {', '.join(missing_provenance_stage_ids)}\n")
PY

suite_digest="$(hash_string "suite-complete|${TRACE_ID}|${SUMMARY_JSON}")"
suite_status="pass"
if ! jq -e '.verdict == "PASS"' "${SUMMARY_JSON}" >/dev/null; then
  suite_status="fail"
fi

log_event \
  "CAPSULE_VERIFY_SUITE_COMPLETE" \
  "suite" \
  "${suite_status}" \
  "suite-bd-1z5a" \
  "operator-e2e" \
  "bd-1z5a" \
  "${suite_digest}" \
  "observe" \
  "SUITE_COMPLETE" \
  "" \
  "tests/e2e/verifier_replay_operator_suite.sh" \
  "completed bd-1z5a operator E2E suite"

echo "bd-1z5a.3 operator E2E: $(jq -r '.verdict' "${SUMMARY_JSON}") ($(jq -r '.pass_count' "${SUMMARY_JSON}")/$(jq -r '.stage_count' "${SUMMARY_JSON}") stages passed)"
[ "$(jq -r '.verdict' "${SUMMARY_JSON}")" = "PASS" ]
