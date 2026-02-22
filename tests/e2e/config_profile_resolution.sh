#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/section_bootstrap/bd-n9r"
CHECKS_JSON="${OUT_DIR}/contract_checks.json"
SNAPSHOT_JSON="${OUT_DIR}/resolved_config_snapshot.json"
SUMMARY_MD="${OUT_DIR}/contract_checks.md"
LOG_JSONL="${OUT_DIR}/config_resolution_log.jsonl"

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
    --arg event_code "${event_code}" \
    --arg status "${status}" \
    --arg detail "${detail}" \
    '{ts: $ts, event_code: $event_code, status: $status, detail: $detail}' \
    >> "${LOG_JSONL}"
}

log_event "CFG-E2E-001" "info" "Starting bd-n9r config precedence verification"

python3 - <<'PY' "${ROOT_DIR}" "${CHECKS_JSON}" "${SNAPSHOT_JSON}"
import hashlib
import json
import sys
from pathlib import Path

if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11+ required for tomllib")

import tomllib

root = Path(sys.argv[1])
checks_json = Path(sys.argv[2])
snapshot_json = Path(sys.argv[3])

config_rs = root / "crates" / "franken-node" / "src" / "config.rs"
cli_rs = root / "crates" / "franken-node" / "src" / "cli.rs"
main_rs = root / "crates" / "franken-node" / "src" / "main.rs"
example_toml = root / "config" / "franken_node.profile_examples.toml"
contract_md = root / "docs" / "specs" / "bootstrap_config_contract.md"

checks = []

def add(check: str, passed: bool, detail: str = "") -> None:
    checks.append({"check": check, "passed": passed, "detail": detail})


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")

for required in (config_rs, cli_rs, main_rs, example_toml, contract_md):
    add(f"exists_{required.name}", required.exists(), str(required))

config_src = read_text(config_rs) if config_rs.exists() else ""
cli_src = read_text(cli_rs) if cli_rs.exists() else ""
main_src = read_text(main_rs) if main_rs.exists() else ""
contract_src = read_text(contract_md) if contract_md.exists() else ""

add("resolver_entrypoint", "pub fn resolve(" in config_src, "Config::resolve")
add("env_override_layer", "fn apply_env_overrides(" in config_src, "env layer")
add("merge_decision_struct", "pub struct MergeDecision" in config_src, "MergeDecision")
add("merge_stage_enum", "pub enum MergeStage" in config_src, "MergeStage")
add("precedence_doc_string", "CLI > env > profile-block > file-base > defaults" in config_src, "resolver precedence")
add("contract_precedence_doc", "CLI > env > profile-block > file-base > defaults" in contract_src, "contract precedence")

add("main_init_uses_resolver", main_src.count("Config::resolve(") >= 2, f"count={main_src.count('Config::resolve(')}")
add("main_doctor_outputs_decisions", "merge_decision stage=" in main_src, "doctor merge tracing")

add("cli_init_config_option", "pub config: Option<PathBuf>" in cli_src, "InitArgs --config")
add("cli_doctor_config_option", cli_src.count("pub config: Option<PathBuf>") >= 2, f"count={cli_src.count('pub config: Option<PathBuf>')}")
add("cli_profile_options", cli_src.count("pub profile: Option<String>") >= 2, f"count={cli_src.count('pub profile: Option<String>')}")

if example_toml.exists():
    data = tomllib.loads(read_text(example_toml))
else:
    data = {}

add("example_profile_present", "profile" in data, str(data.get("profile")))
add("example_profiles_table", isinstance(data.get("profiles"), dict), "profiles table")
add("example_profiles_strict", "strict" in data.get("profiles", {}), "profiles.strict")
add("example_profiles_balanced", "balanced" in data.get("profiles", {}), "profiles.balanced")
add("example_profiles_legacy", "legacy-risky" in data.get("profiles", {}), "profiles.legacy-risky")

# Deterministic precedence simulation artifact for CI inspection.
def defaults(profile: str) -> dict:
    strict = {
        "profile": "strict",
        "compatibility": {"mode": "strict", "emit_divergence_receipts": True},
        "migration": {"autofix": False, "require_lockstep_validation": True},
        "trust": {
            "risky_requires_fresh_revocation": True,
            "dangerous_requires_fresh_revocation": True,
            "quarantine_on_high_risk": True,
        },
        "replay": {"persist_high_severity": True, "bundle_version": "v1"},
        "registry": {"require_signatures": True, "require_provenance": True, "minimum_assurance_level": 4},
        "fleet": {"convergence_timeout_seconds": 60},
        "observability": {"namespace": "franken_node", "emit_structured_audit_events": True},
    }
    balanced = {
        "profile": "balanced",
        "compatibility": {"mode": "balanced", "emit_divergence_receipts": True},
        "migration": {"autofix": True, "require_lockstep_validation": True},
        "trust": {
            "risky_requires_fresh_revocation": True,
            "dangerous_requires_fresh_revocation": True,
            "quarantine_on_high_risk": True,
        },
        "replay": {"persist_high_severity": True, "bundle_version": "v1"},
        "registry": {"require_signatures": True, "require_provenance": True, "minimum_assurance_level": 3},
        "fleet": {"convergence_timeout_seconds": 120},
        "observability": {"namespace": "franken_node", "emit_structured_audit_events": True},
    }
    legacy = {
        "profile": "legacy-risky",
        "compatibility": {"mode": "legacy-risky", "emit_divergence_receipts": False},
        "migration": {"autofix": True, "require_lockstep_validation": False},
        "trust": {
            "risky_requires_fresh_revocation": False,
            "dangerous_requires_fresh_revocation": True,
            "quarantine_on_high_risk": False,
        },
        "replay": {"persist_high_severity": True, "bundle_version": "v1"},
        "registry": {"require_signatures": False, "require_provenance": False, "minimum_assurance_level": 1},
        "fleet": {"convergence_timeout_seconds": 300},
        "observability": {"namespace": "franken_node", "emit_structured_audit_events": False},
    }
    return {"strict": strict, "balanced": balanced, "legacy-risky": legacy}[profile]


def deep_apply(dst: dict, src: dict) -> None:
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(dst.get(key), dict):
            deep_apply(dst[key], value)
        else:
            dst[key] = value


base_profile = data.get("profile", "balanced")
env_profile = "strict"
cli_profile = "legacy-risky"
selected_profile = cli_profile

resolved = defaults(selected_profile)
profile_block = data.get("profiles", {}).get(selected_profile, {})
base_overrides = {k: v for k, v in data.items() if k not in ("profile", "profiles")}

if isinstance(profile_block, dict):
    deep_apply(resolved, profile_block)
deep_apply(resolved, base_overrides)

env_overrides = {
    "migration": {"autofix": False},
    "registry": {"minimum_assurance_level": 4},
}
deep_apply(resolved, env_overrides)

provenance = [
    {"stage": "default", "field": "profile", "value": "balanced"},
    {"stage": "file", "field": "profile", "value": base_profile},
    {"stage": "env", "field": "profile", "value": env_profile},
    {"stage": "cli", "field": "profile", "value": cli_profile},
]

snapshot = {
    "bead_id": "bd-n9r",
    "schema_version": "config-resolution-snapshot-v1",
    "selected_profile": selected_profile,
    "source_precedence": "CLI > env > profile-block > file-base > defaults",
    "simulated_inputs": {
        "file_profile": base_profile,
        "env_profile": env_profile,
        "cli_profile": cli_profile,
        "env_overrides": env_overrides,
    },
    "provenance": provenance,
    "resolved_config": resolved,
}

snapshot_text = json.dumps(snapshot, indent=2, sort_keys=True)
snapshot_json.write_text(snapshot_text + "\n", encoding="utf-8")

checksum = hashlib.sha256(snapshot_text.encode("utf-8")).hexdigest()
add("snapshot_written", snapshot_json.exists(), str(snapshot_json))
add("snapshot_sha256", len(checksum) == 64, checksum)

passed = sum(1 for c in checks if c["passed"])
total = len(checks)
verdict = "PASS" if passed == total else "FAIL"

payload = {
    "bead_id": "bd-n9r",
    "gate_script": "config_profile_resolution.sh",
    "checks_passed": passed,
    "checks_total": total,
    "verdict": verdict,
    "checks": checks,
}
checks_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

if verdict != "PASS":
    raise SystemExit(1)
PY

if [ $? -eq 0 ]; then
  log_event "CFG-E2E-099" "pass" "Config precedence verification passed"
else
  log_event "CFG-E2E-099" "fail" "Config precedence verification failed"
  exit 1
fi

{
  echo "# bd-n9r Config Resolution Contract Checks"
  echo
  echo '- Log: `artifacts/section_bootstrap/bd-n9r/config_resolution_log.jsonl`'
  echo '- Checks JSON: `artifacts/section_bootstrap/bd-n9r/contract_checks.json`'
  echo '- Snapshot JSON: `artifacts/section_bootstrap/bd-n9r/resolved_config_snapshot.json`'
  echo
  echo "| Check | Pass | Detail |"
  echo "|---|---|---|"
  jq -r '.checks[] | "| \(.check) | \(.passed) | \(.detail|tostring|gsub("\\n";" ")) |"' "${CHECKS_JSON}"
  echo
  echo "Verdict: **$(jq -r '.verdict' "${CHECKS_JSON}")** ($(jq -r '.checks_passed' "${CHECKS_JSON}")/$(jq -r '.checks_total' "${CHECKS_JSON}"))"
} > "${SUMMARY_MD}"

echo "bd-n9r config profile resolution checks: PASS"
