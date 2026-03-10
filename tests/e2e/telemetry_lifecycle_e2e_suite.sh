#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Telemetry Bridge E2E Orchestration Suite (bd-1now.4.6)
#
# Exercises the full telemetry bridge lifecycle through representative operator
# scenarios, capturing machine-readable summaries and human-readable logs as
# build artifacts.
#
# Scenarios exercised:
#   1. Normal startup → ingestion → orderly shutdown
#   2. Abnormal engine exit (non-zero exit code, signal kill)
#   3. Burst traffic hitting backpressure/overflow policy
#   4. Oversized event rejection
#   5. Multi-connection concurrent ingestion
#   6. Socket cleanup and worker-resolution after stop/join
#   7. Lifecycle state transition recording
#   8. Persistence key format verification
#   9. Stale socket recovery
#
# Usage:
#   ./tests/e2e/telemetry_lifecycle_e2e_suite.sh
#   TRACE_ID=custom-trace ./tests/e2e/telemetry_lifecycle_e2e_suite.sh
#
# Artifacts written to: artifacts/asupersync/bd-1now.4.6/
# ============================================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/asupersync/bd-1now.4.6"
STAGES_DIR="${OUT_DIR}/stage_outputs"
LOG_JSONL="${OUT_DIR}/telemetry_e2e_log.jsonl"
RESULTS_JSONL="${OUT_DIR}/telemetry_e2e_stage_results.jsonl"
SUMMARY_JSON="${OUT_DIR}/telemetry_e2e_summary.json"
SUMMARY_MD="${OUT_DIR}/telemetry_e2e_summary.md"
TRACE_ID="${TRACE_ID:-trace-bd-1now-4-6-telemetry-e2e}"

mkdir -p "${OUT_DIR}" "${STAGES_DIR}"
: > "${LOG_JSONL}"
: > "${RESULTS_JSONL}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required" >&2
  exit 2
fi

# ---- Logging helpers ----

log_event() {
  local event_code="$1"
  local stage="$2"
  local status="$3"
  local detail="$4"
  python3 - "$LOG_JSONL" "$TRACE_ID" "$event_code" "$stage" "$status" "$detail" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

path = Path(sys.argv[1])
payload = {
    "ts": datetime.now(timezone.utc).isoformat(),
    "trace_id": sys.argv[2],
    "event_code": sys.argv[3],
    "stage": sys.argv[4],
    "status": sys.argv[5],
    "detail": sys.argv[6],
}
with path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(payload) + "\n")
PY
}

record_stage_result() {
  local stage="$1"
  local status="$2"
  local detail="$3"
  local elapsed="$4"
  python3 - "$RESULTS_JSONL" "$TRACE_ID" "$stage" "$status" "$detail" "$elapsed" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

path = Path(sys.argv[1])
payload = {
    "ts": datetime.now(timezone.utc).isoformat(),
    "trace_id": sys.argv[2],
    "stage": sys.argv[3],
    "status": sys.argv[4],
    "detail": sys.argv[5],
    "elapsed_seconds": float(sys.argv[6]),
}
with path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(payload) + "\n")
PY
}

TOTAL_STAGES=0
PASSED_STAGES=0
FAILED_STAGES=0
STAGE_START_TIME=0

start_stage() {
  STAGE_START_TIME=$(date +%s)
  log_event "E2E_STAGE_START" "$1" "running" "$2"
  echo "  [$1] $2..."
}

finish_stage() {
  local stage="$1"
  local status="$2"
  local detail="$3"
  local elapsed=$(( $(date +%s) - STAGE_START_TIME ))
  TOTAL_STAGES=$((TOTAL_STAGES + 1))
  if [ "$status" = "pass" ]; then
    PASSED_STAGES=$((PASSED_STAGES + 1))
    echo "  [$stage] PASS (${elapsed}s)"
  else
    FAILED_STAGES=$((FAILED_STAGES + 1))
    echo "  [$stage] FAIL: $detail (${elapsed}s)"
  fi
  log_event "E2E_STAGE_COMPLETE" "$stage" "$status" "$detail"
  record_stage_result "$stage" "$status" "$detail" "$elapsed"
}

# ---- Stage: Compile check ----

echo "=========================================="
echo "Telemetry Bridge E2E Suite"
echo "Trace ID: ${TRACE_ID}"
echo "Artifacts: ${OUT_DIR}"
echo "=========================================="
echo ""
log_event "E2E_SUITE_START" "init" "running" "starting telemetry E2E suite"

start_stage "compile" "Verify telemetry_bridge module compiles with clippy"
CLIPPY_OUTPUT="${STAGES_DIR}/clippy_output.txt"
if cargo clippy -p frankenengine-node --lib -- -D warnings > "${CLIPPY_OUTPUT}" 2>&1; then
  finish_stage "compile" "pass" "clippy clean for frankenengine-node"
else
  finish_stage "compile" "fail" "clippy returned warnings or errors"
fi

# ---- Stage: Unit test baseline ----

start_stage "unit-baseline" "Run all telemetry_bridge unit tests"
UNIT_OUTPUT="${STAGES_DIR}/unit_test_output.txt"
if cargo test -p frankenengine-node --lib ops::telemetry_bridge -- --nocapture > "${UNIT_OUTPUT}" 2>&1; then
  UNIT_COUNT=$(grep -c '^\btest .* ok$' "${UNIT_OUTPUT}" 2>/dev/null || echo "0")
  finish_stage "unit-baseline" "pass" "${UNIT_COUNT} unit tests passed"
else
  finish_stage "unit-baseline" "fail" "unit tests failed"
fi

# ---- Stage: Normal startup → ingestion → orderly shutdown ----

start_stage "normal-lifecycle" "End-to-end single event ingestion and orderly shutdown"
NORMAL_OUTPUT="${STAGES_DIR}/normal_lifecycle.txt"
if cargo test -p frankenengine-node --lib ops::telemetry_bridge::tests::end_to_end_single_event_ingestion -- --nocapture > "${NORMAL_OUTPUT}" 2>&1; then
  finish_stage "normal-lifecycle" "pass" "single event ingested and persisted"
else
  finish_stage "normal-lifecycle" "fail" "ingestion or persistence failed"
fi

# ---- Stage: Multi-event ingestion ----

start_stage "multi-event" "End-to-end multiple event ingestion"
MULTI_OUTPUT="${STAGES_DIR}/multi_event.txt"
if cargo test -p frankenengine-node --lib ops::telemetry_bridge::tests::end_to_end_multiple_events_ingestion -- --nocapture > "${MULTI_OUTPUT}" 2>&1; then
  finish_stage "multi-event" "pass" "10 events ingested sequentially"
else
  finish_stage "multi-event" "fail" "multi-event ingestion failed"
fi

# ---- Stage: Abnormal engine termination ----

start_stage "abnormal-exit" "Engine exit with non-zero code and signal kill"
ABNORMAL_OUTPUT="${STAGES_DIR}/abnormal_exit.txt"
if cargo test -p frankenengine-node --lib ops::telemetry_bridge::tests::socket_cleaned_up_after_engine_exit_failure -- --nocapture > "${ABNORMAL_OUTPUT}" 2>&1 && \
   cargo test -p frankenengine-node --lib ops::telemetry_bridge::tests::socket_cleaned_up_after_engine_signal_kill -- --nocapture >> "${ABNORMAL_OUTPUT}" 2>&1; then
  finish_stage "abnormal-exit" "pass" "clean shutdown after engine failure and signal kill"
else
  finish_stage "abnormal-exit" "fail" "abnormal exit handling broken"
fi

# ---- Stage: Burst traffic / backpressure ----

start_stage "backpressure" "Burst traffic exceeding queue capacity"
BURST_OUTPUT="${STAGES_DIR}/backpressure.txt"
if cargo test -p frankenengine-node --lib ops::telemetry_bridge::tests::backpressure_burst_events_shed_cleanly -- --nocapture > "${BURST_OUTPUT}" 2>&1; then
  finish_stage "backpressure" "pass" "burst events shed cleanly under backpressure"
else
  finish_stage "backpressure" "fail" "backpressure handling broken"
fi

# ---- Stage: Oversized event rejection ----

start_stage "oversized-reject" "Event exceeding MAX_EVENT_BYTES is shed"
OVERSIZED_OUTPUT="${STAGES_DIR}/oversized_reject.txt"
if cargo test -p frankenengine-node --lib ops::telemetry_bridge::tests::oversized_event_rejected_with_shed -- --nocapture > "${OVERSIZED_OUTPUT}" 2>&1; then
  finish_stage "oversized-reject" "pass" "oversized event rejected with shed counter"
else
  finish_stage "oversized-reject" "fail" "oversized event not properly rejected"
fi

# ---- Stage: Multi-connection concurrent ingestion ----

start_stage "multi-conn" "5 concurrent connections × 3 events each"
MULTICONN_OUTPUT="${STAGES_DIR}/multi_conn.txt"
if cargo test -p frankenengine-node --lib ops::telemetry_bridge::tests::multi_connection_concurrent_ingestion -- --nocapture > "${MULTICONN_OUTPUT}" 2>&1; then
  finish_stage "multi-conn" "pass" "15 events from 5 connections ingested concurrently"
else
  finish_stage "multi-conn" "fail" "concurrent ingestion failed"
fi

# ---- Stage: Socket cleanup and worker resolution ----

start_stage "worker-cleanup" "Socket cleanup and no-orphan-workers after stop/join"
CLEANUP_OUTPUT="${STAGES_DIR}/worker_cleanup.txt"
if cargo test -p frankenengine-node --lib ops::telemetry_bridge::tests::socket_cleaned_up_after_normal_shutdown -- --nocapture > "${CLEANUP_OUTPUT}" 2>&1 && \
   cargo test -p frankenengine-node --lib ops::telemetry_bridge::tests::no_orphan_workers_after_stop_and_join -- --nocapture >> "${CLEANUP_OUTPUT}" 2>&1; then
  finish_stage "worker-cleanup" "pass" "workers joined and state refs released"
else
  finish_stage "worker-cleanup" "fail" "orphan worker or cleanup failure"
fi

# ---- Stage: Lifecycle state transitions ----

start_stage "transitions" "Lifecycle state transition events recorded"
TRANS_OUTPUT="${STAGES_DIR}/transitions.txt"
if cargo test -p frankenengine-node --lib ops::telemetry_bridge::tests::lifecycle_transitions_are_recorded_in_events -- --nocapture > "${TRANS_OUTPUT}" 2>&1; then
  finish_stage "transitions" "pass" "LISTENER_STARTED → STATE_TRANSITION → DRAIN_STARTED → DRAIN_COMPLETE"
else
  finish_stage "transitions" "fail" "lifecycle transition events missing"
fi

# ---- Stage: Persistence key format ----

start_stage "key-format" "Persistence keys are zero-padded sequential"
KEY_OUTPUT="${STAGES_DIR}/key_format.txt"
if cargo test -p frankenengine-node --lib ops::telemetry_bridge::tests::persistence_key_format_is_sequential -- --nocapture > "${KEY_OUTPUT}" 2>&1; then
  finish_stage "key-format" "pass" "keys follow telemetry_NNNNN format"
else
  finish_stage "key-format" "fail" "key format verification failed"
fi

# ---- Stage: Stale socket recovery ----

start_stage "stale-recovery" "Start succeeds despite pre-existing stale socket"
STALE_OUTPUT="${STAGES_DIR}/stale_recovery.txt"
if cargo test -p frankenengine-node --lib ops::telemetry_bridge::tests::stale_socket_cleanup_before_start -- --nocapture > "${STALE_OUTPUT}" 2>&1; then
  finish_stage "stale-recovery" "pass" "stale socket cleaned up before bind"
else
  finish_stage "stale-recovery" "fail" "stale socket prevented startup"
fi

# ---- Stage: Structured event fields ----

start_stage "event-fields" "All events contain required forensic fields"
FIELDS_OUTPUT="${STAGES_DIR}/event_fields.txt"
if cargo test -p frankenengine-node --lib ops::telemetry_bridge::tests::structured_events_contain_required_fields -- --nocapture > "${FIELDS_OUTPUT}" 2>&1; then
  finish_stage "event-fields" "pass" "bridge_id, code, detail, queue_capacity present"
else
  finish_stage "event-fields" "fail" "structured event fields missing"
fi

# ---- Generate summary ----

echo ""
echo "=========================================="
echo "Summary: ${PASSED_STAGES}/${TOTAL_STAGES} stages passed"
echo "=========================================="

python3 - "${SUMMARY_JSON}" "${SUMMARY_MD}" "${RESULTS_JSONL}" "${TRACE_ID}" \
  "${TOTAL_STAGES}" "${PASSED_STAGES}" "${FAILED_STAGES}" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

summary_json_path = Path(sys.argv[1])
summary_md_path = Path(sys.argv[2])
results_path = Path(sys.argv[3])
trace_id = sys.argv[4]
total = int(sys.argv[5])
passed = int(sys.argv[6])
failed = int(sys.argv[7])

stages = []
if results_path.exists():
    for line in results_path.read_text().strip().splitlines():
        stages.append(json.loads(line))

summary = {
    "ts": datetime.now(timezone.utc).isoformat(),
    "trace_id": trace_id,
    "suite": "telemetry_lifecycle_e2e",
    "bead": "bd-1now.4.6",
    "total_stages": total,
    "passed": passed,
    "failed": failed,
    "verdict": "PASS" if failed == 0 else "FAIL",
    "stages": stages,
}

with summary_json_path.open("w", encoding="utf-8") as fh:
    json.dump(summary, fh, indent=2)
    fh.write("\n")

lines = [
    f"# Telemetry Bridge E2E Summary",
    f"",
    f"- **Trace ID**: `{trace_id}`",
    f"- **Bead**: bd-1now.4.6",
    f"- **Verdict**: {'PASS' if failed == 0 else 'FAIL'}",
    f"- **Stages**: {passed}/{total} passed",
    f"",
    f"## Stage Results",
    f"",
    f"| Stage | Status | Detail | Elapsed |",
    f"|-------|--------|--------|---------|",
]
for s in stages:
    icon = "+" if s["status"] == "pass" else "X"
    lines.append(
        f"| {s['stage']} | {icon} {s['status'].upper()} | {s['detail']} | {s['elapsed_seconds']}s |"
    )

lines.extend([
    f"",
    f"## Artifact Locations",
    f"",
    f"- Machine-readable summary: `artifacts/asupersync/bd-1now.4.6/telemetry_e2e_summary.json`",
    f"- Stage results (JSONL): `artifacts/asupersync/bd-1now.4.6/telemetry_e2e_stage_results.jsonl`",
    f"- Event log (JSONL): `artifacts/asupersync/bd-1now.4.6/telemetry_e2e_log.jsonl`",
    f"- Per-stage outputs: `artifacts/asupersync/bd-1now.4.6/stage_outputs/`",
    f"",
    f"## Scenarios Covered",
    f"",
    f"1. Normal startup, ingestion, orderly shutdown",
    f"2. Abnormal engine exit (non-zero code, signal kill)",
    f"3. Burst traffic exceeding backpressure capacity",
    f"4. Oversized event rejection (>64KB)",
    f"5. Multi-connection concurrent ingestion",
    f"6. Socket cleanup and worker-resolution after stop/join",
    f"7. Lifecycle state transition recording",
    f"8. Persistence key format verification",
    f"9. Stale socket recovery",
    f"10. Structured event field validation",
    "",
])
with summary_md_path.open("w", encoding="utf-8") as fh:
    fh.write("\n".join(lines))

PY

log_event "E2E_SUITE_COMPLETE" "summary" \
  "$([ "$FAILED_STAGES" -eq 0 ] && echo pass || echo fail)" \
  "${PASSED_STAGES}/${TOTAL_STAGES} stages passed"

echo ""
echo "Artifacts written to: ${OUT_DIR}"
echo "  - ${SUMMARY_JSON}"
echo "  - ${SUMMARY_MD}"
echo "  - ${LOG_JSONL}"
echo "  - ${RESULTS_JSONL}"
echo ""

if [ "${FAILED_STAGES}" -gt 0 ]; then
  echo "FAIL: ${FAILED_STAGES} stage(s) failed"
  exit 1
fi
echo "All stages passed."
