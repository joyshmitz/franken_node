#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/asupersync/bd-1now.3.2"
STAGES_DIR="${OUT_DIR}/stage_outputs"
LOG_JSONL="${OUT_DIR}/tokio_guardrail_e2e_log.jsonl"
RESULTS_JSONL="${OUT_DIR}/tokio_guardrail_stage_results.jsonl"
SUMMARY_JSON="${OUT_DIR}/tokio_guardrail_e2e_summary.json"
SUMMARY_MD="${OUT_DIR}/tokio_guardrail_e2e_summary.md"
TRACE_ID="${TRACE_ID:-trace-bd-1now-3-2-tokio-guardrail}"
WORK_DIR="${OUT_DIR}/workspaces/${TRACE_ID}"
SRC_DIR="${WORK_DIR}/src"
BLUEPRINT_PATH="${WORK_DIR}/blueprint.md"
CHECKER="${ROOT_DIR}/scripts/check_tokio_bootstrap_guardrail.py"

mkdir -p "${OUT_DIR}" "${STAGES_DIR}" "${SRC_DIR}" "${WORK_DIR}"
: > "${LOG_JSONL}"
: > "${RESULTS_JSONL}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required" >&2
  exit 2
fi

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

write_blueprint() {
  cat > "${BLUEPRINT_PATH}" <<'EOF'
## 8.6 Selective Asupersync Leverage Decision Record

Selective Asupersync record.

### Runtime Guardrail Exception Path

1. Update the blueprint.
2. Update the checker.
3. Add proof.
EOF
}

write_main() {
  local content="$1"
  mkdir -p "${SRC_DIR}"
  printf '%s\n' "${content}" > "${SRC_DIR}/main.rs"
}

run_stage() {
  local stage_id="$1"
  local expected_exit="$2"
  local expected_verdict="$3"
  local expected_reason="${4:-}"
  local source_content="$5"

  local stdout_path="${STAGES_DIR}/${stage_id}.stdout.json"
  local stderr_path="${STAGES_DIR}/${stage_id}.stderr.log"

  write_blueprint
  write_main "${source_content}"
  log_event "TKG-E2E-010" "${stage_id}" "start" "stage start"

  set +e
  TOKIO_BOOTSTRAP_GUARDRAIL_SOURCE_ROOT="${SRC_DIR}" \
  TOKIO_BOOTSTRAP_GUARDRAIL_BLUEPRINT="${BLUEPRINT_PATH}" \
    python3 "${CHECKER}" --json >"${stdout_path}" 2>"${stderr_path}"
  local actual_exit=$?
  set -e

  python3 - "$RESULTS_JSONL" "$stage_id" "$expected_exit" "$actual_exit" "$expected_verdict" "$expected_reason" "$stdout_path" "$stderr_path" <<'PY'
import json
import sys
from pathlib import Path

results_path = Path(sys.argv[1])
stage_id = sys.argv[2]
expected_exit = int(sys.argv[3])
actual_exit = int(sys.argv[4])
expected_verdict = sys.argv[5]
expected_reason = sys.argv[6]
stdout_path = Path(sys.argv[7])
stderr_path = Path(sys.argv[8])

payload = json.loads(stdout_path.read_text(encoding="utf-8"))
reason_codes = [item["reason_code"] for item in payload.get("violations", [])]
status = "pass"
if actual_exit != expected_exit:
    status = "fail"
elif payload.get("verdict") != expected_verdict:
    status = "fail"
elif expected_reason and expected_reason not in reason_codes:
    status = "fail"

record = {
    "stage_id": stage_id,
    "expected_exit": expected_exit,
    "actual_exit": actual_exit,
    "expected_verdict": expected_verdict,
    "actual_verdict": payload.get("verdict"),
    "expected_reason": expected_reason or None,
    "reason_codes": reason_codes,
    "status": status,
    "stdout_path": stdout_path.as_posix(),
    "stderr_path": stderr_path.as_posix(),
}
with results_path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(record) + "\n")

if status != "pass":
    print(json.dumps(record, indent=2))
    raise SystemExit(1)
PY

  log_event "TKG-E2E-020" "${stage_id}" "pass" "stage pass"
}

log_event "TKG-E2E-001" "suite" "start" "starting tokio bootstrap guardrail e2e suite"

run_stage \
  "allowed_clean_tree" \
  "0" \
  "PASS" \
  "" \
  $'fn main() {\n    // #[tokio::main]\n    let _message = "tokio::runtime::Builder::new_current_thread()";\n}'

run_stage \
  "forbidden_tokio_main" \
  "1" \
  "FAIL" \
  "TKG-001" \
  $'#[tokio::main]\nasync fn main() {}'

run_stage \
  "forbidden_aliased_builder" \
  "1" \
  "FAIL" \
  "TKG-006" \
  $'use tokio::runtime::{Builder as TokioBuilder};\nfn main() {\n    let _ = TokioBuilder::new_current_thread();\n}'

python3 - "$RESULTS_JSONL" "$SUMMARY_JSON" "$SUMMARY_MD" "$TRACE_ID" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

results_path = Path(sys.argv[1])
summary_path = Path(sys.argv[2])
summary_md_path = Path(sys.argv[3])
trace_id = sys.argv[4]

stage_results = [
    json.loads(line)
    for line in results_path.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

pass_count = sum(1 for row in stage_results if row["status"] == "pass")
fail_count = len(stage_results) - pass_count
summary = {
    "trace_id": trace_id,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "stage_count": len(stage_results),
    "pass_count": pass_count,
    "fail_count": fail_count,
    "stages": stage_results,
    "verdict": "PASS" if fail_count == 0 else "FAIL",
}
summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
summary_md_path.write_text(
    "\n".join(
        [
            "# Tokio Bootstrap Guardrail E2E Summary",
            "",
            f"- trace_id: `{trace_id}`",
            f"- stage_count: `{len(stage_results)}`",
            f"- pass_count: `{pass_count}`",
            f"- fail_count: `{fail_count}`",
            f"- verdict: `{'PASS' if fail_count == 0 else 'FAIL'}`",
        ]
    )
    + "\n",
    encoding="utf-8",
)
PY

log_event "TKG-E2E-999" "suite" "pass" "tokio bootstrap guardrail e2e suite complete"
echo "tokio bootstrap guardrail e2e suite PASS"
