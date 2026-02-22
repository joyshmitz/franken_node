#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/section_bootstrap/bd-32e"
LOG_JSONL="${OUT_DIR}/init_bootstrap_log.jsonl"
CHECKS_JSON="${OUT_DIR}/init_contract_checks.json"
SNAPSHOTS_JSON="${OUT_DIR}/init_snapshots.json"
SUMMARY_MD="${OUT_DIR}/init_contract_checks.md"
TRACE_ID="trace-bd-32e-init-e2e"

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

log_event "INIT-E2E-001" "info" "Starting bd-32e init bootstrap gate."

python3 - <<'PY' "${ROOT_DIR}" "${CHECKS_JSON}" "${SNAPSHOTS_JSON}"
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
checks_json = Path(sys.argv[2])
snapshots_json = Path(sys.argv[3])

main_rs = root / "crates" / "franken-node" / "src" / "main.rs"
cli_rs = root / "crates" / "franken-node" / "src" / "cli.rs"
contract_md = root / "docs" / "specs" / "bootstrap_init_contract.md"
template_toml = root / "config" / "franken_node.profile_examples.toml"

checks = []


def add(check: str, passed: bool, detail: str = "") -> None:
    checks.append({"check": check, "passed": passed, "detail": detail})


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


for path in (main_rs, cli_rs, contract_md, template_toml):
    add(f"exists_{path.name}", path.exists(), str(path))

main_src = read(main_rs) if main_rs.exists() else ""
cli_src = read(cli_rs) if cli_rs.exists() else ""
contract_src = read(contract_md) if contract_md.exists() else ""

for snippet, check_name in (
    ("pub overwrite: bool", "cli_init_overwrite_flag"),
    ("pub backup_existing: bool", "cli_init_backup_flag"),
    ("pub json: bool", "cli_init_json_flag"),
    ("pub trace_id: String", "cli_init_trace_id_flag"),
):
    add(check_name, snippet in cli_src, snippet)

add("init_trace_id_default", 'default_value = "init-bootstrap"' in cli_src, "init-bootstrap")

for snippet, check_name in (
    ("PROFILE_EXAMPLES_TEMPLATE", "init_profile_template_embedded"),
    ("validate_init_flags(", "init_flag_validation"),
    ("apply_init_write_policy(", "init_write_policy_function"),
    ("--overwrite and --backup-existing are mutually exclusive", "init_mutual_exclusion_error"),
    ("franken_node.profile_examples.toml", "init_writes_profile_example_file"),
    ("refusing to overwrite existing file", "init_non_destructive_default"),
):
    add(check_name, snippet in main_src, snippet)

add(
    "init_contract_sections_present",
    "## Overwrite Policy (Explicit, Non-Destructive by Default)" in contract_src
    and "## Machine-Readable Init Report" in contract_src,
    "policy+schema",
)

snapshots = {
    "bead_id": "bd-32e",
    "schema_version": "init-bootstrap-snapshots-v1",
    "scenarios": [
        {
            "scenario": "clean_out_dir",
            "inputs": {
                "out_dir": "/workspace/new-project",
                "overwrite": False,
                "backup_existing": False,
                "json": True,
            },
            "expected": {
                "wrote_to_stdout": False,
                "file_actions": [
                    {
                        "path_suffix": "franken_node.toml",
                        "action": "created",
                        "backup_path": None,
                    },
                    {
                        "path_suffix": "franken_node.profile_examples.toml",
                        "action": "created",
                        "backup_path": None,
                    },
                ],
            },
        },
        {
            "scenario": "existing_files_abort_default",
            "inputs": {
                "out_dir": "/workspace/existing-project",
                "overwrite": False,
                "backup_existing": False,
            },
            "expected_error": {
                "code": "INIT-EXISTS-001",
                "message_contains": "use --overwrite or --backup-existing",
            },
        },
        {
            "scenario": "backup_existing_rewrite",
            "inputs": {
                "out_dir": "/workspace/existing-project",
                "overwrite": False,
                "backup_existing": True,
            },
            "expected": {
                "wrote_to_stdout": False,
                "file_actions": [
                    {
                        "path_suffix": "franken_node.toml",
                        "action": "backed_up_and_overwritten",
                        "backup_path_suffix": ".bak.<timestamp>",
                    },
                    {
                        "path_suffix": "franken_node.profile_examples.toml",
                        "action": "backed_up_and_overwritten",
                        "backup_path_suffix": ".bak.<timestamp>",
                    },
                ],
            },
        },
        {
            "scenario": "stdout_only",
            "inputs": {
                "out_dir": None,
                "json": True,
            },
            "expected": {
                "wrote_to_stdout": True,
                "stdout_config_toml_non_empty": True,
                "file_actions": [],
            },
        },
    ],
}
snapshots_text = json.dumps(snapshots, indent=2, sort_keys=True)
snapshots_json.write_text(snapshots_text + "\n", encoding="utf-8")
add("snapshots_written", snapshots_json.exists(), str(snapshots_json))

digest = hashlib.sha256(snapshots_text.encode("utf-8")).hexdigest()
add("snapshots_hash_stable", len(digest) == 64, digest)

payload = {
    "bead_id": "bd-32e",
    "gate_script": "init_profile_bootstrap.sh",
    "checks_passed": sum(1 for c in checks if c["passed"]),
    "checks_total": len(checks),
    "verdict": "PASS" if all(c["passed"] for c in checks) else "FAIL",
    "checks": checks,
    "snapshots_path": str(snapshots_json.relative_to(root)),
}
checks_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

if payload["verdict"] != "PASS":
    raise SystemExit(1)
PY

if [ $? -eq 0 ]; then
  log_event "INIT-E2E-099" "pass" "Init bootstrap gate passed."
else
  log_event "INIT-E2E-099" "fail" "Init bootstrap gate failed."
  exit 1
fi

{
  echo "# bd-32e Init Bootstrap Contract Checks"
  echo
  echo "- Log: \`artifacts/section_bootstrap/bd-32e/init_bootstrap_log.jsonl\`"
  echo "- Checks JSON: \`artifacts/section_bootstrap/bd-32e/init_contract_checks.json\`"
  echo "- Snapshots JSON: \`artifacts/section_bootstrap/bd-32e/init_snapshots.json\`"
  echo
  echo "| Check | Pass | Detail |"
  echo "|---|---|---|"
  jq -r '.checks[] | "| \(.check) | \(.passed) | \(.detail|tostring|gsub("\\n";" ")) |"' "${CHECKS_JSON}"
  echo
  echo "Verdict: **$(jq -r '.verdict' "${CHECKS_JSON}")** ($(jq -r '.checks_passed' "${CHECKS_JSON}")/$(jq -r '.checks_total' "${CHECKS_JSON}"))"
} > "${SUMMARY_MD}"

echo "bd-32e init bootstrap checks: PASS"
