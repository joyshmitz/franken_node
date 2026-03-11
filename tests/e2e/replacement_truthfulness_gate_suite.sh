#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TRACE_ID="${TRACE_ID:-trace-bd-3tw7-operator-e2e}"
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}"' EXIT

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required for bd-3tw7 operator E2E checks" >&2
  exit 2
fi

run_fixture() {
  local fixture_root="$1"

  python3 - "$ROOT_DIR" "$fixture_root" "$TRACE_ID" <<'PY'
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys

repo_root = pathlib.Path(sys.argv[1])
fixture_root = pathlib.Path(sys.argv[2])
trace_id = sys.argv[3]


def copy_rel(rel: str) -> None:
    src = repo_root / rel
    dst = fixture_root / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


copy_rel("scripts/check_replacement_truthfulness_gate.py")
copy_rel("scripts/lib/test_logger.py")

spec = importlib.util.spec_from_file_location(
    "truthfulness_gate_fixture",
    fixture_root / "scripts/check_replacement_truthfulness_gate.py",
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)

source_paths = {
    rel
    for witness in module.WITNESS_SPECS
    for rel in witness.source_paths
}
source_paths.update(entry["path"] for entry in module.EXCLUDED_SURFACES)

for rel in sorted(source_paths):
    copy_rel(rel)

env = os.environ.copy()
env["PYTHONDONTWRITEBYTECODE"] = "1"
env["TRACE_ID"] = trace_id

result = subprocess.run(
    [sys.executable, str(fixture_root / "scripts/check_replacement_truthfulness_gate.py"), "--json"],
    cwd=fixture_root,
    env=env,
    capture_output=True,
    text=True,
    check=False,
)

if result.returncode != 0:
    sys.stderr.write(result.stderr)
    sys.stderr.write(result.stdout)
    raise SystemExit(result.returncode)

payload = json.loads(result.stdout)
if not payload.get("overall_pass"):
    raise SystemExit("truthfulness gate payload did not pass")

operator_e2e = payload.get("operator_e2e", {})
if operator_e2e.get("suite") != module.OPERATOR_E2E_SUITE:
    raise SystemExit("operator_e2e suite metadata drifted")

artifacts = payload.get("artifacts", {})
for key in ("verification_evidence", "verification_summary", "witness_matrix", "operator_e2e_suite"):
    rel = artifacts.get(key)
    if not rel:
        raise SystemExit(f"missing artifact key: {key}")
    path = fixture_root / rel
    if key == "operator_e2e_suite":
        path = repo_root / rel
    if not path.exists():
        raise SystemExit(f"expected path missing for {key}: {path}")

payload.pop("generated_at", None)
payload["trace_id"] = trace_id

evidence_path = fixture_root / artifacts["verification_evidence"]
evidence_payload = json.loads(evidence_path.read_text(encoding="utf-8"))
evidence_payload.pop("generated_at", None)
evidence_payload["trace_id"] = trace_id

outputs_dir = fixture_root / "operator_e2e_outputs"
outputs_dir.mkdir(parents=True, exist_ok=True)
outputs_dir.joinpath("payload.normalized.json").write_text(
    json.dumps(payload, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
outputs_dir.joinpath("evidence.normalized.json").write_text(
    json.dumps(evidence_payload, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
shutil.copy2(
    fixture_root / artifacts["verification_summary"],
    outputs_dir / "verification_summary.md",
)
shutil.copy2(
    fixture_root / artifacts["witness_matrix"],
    outputs_dir / "witness_matrix.json",
)
PY
}

RUN_ONE="${TMP_ROOT}/run_one"
RUN_TWO="${TMP_ROOT}/run_two"
mkdir -p "${RUN_ONE}" "${RUN_TWO}"

run_fixture "${RUN_ONE}"
run_fixture "${RUN_TWO}"

cmp -s \
  "${RUN_ONE}/operator_e2e_outputs/payload.normalized.json" \
  "${RUN_TWO}/operator_e2e_outputs/payload.normalized.json"
cmp -s \
  "${RUN_ONE}/operator_e2e_outputs/evidence.normalized.json" \
  "${RUN_TWO}/operator_e2e_outputs/evidence.normalized.json"
cmp -s \
  "${RUN_ONE}/operator_e2e_outputs/verification_summary.md" \
  "${RUN_TWO}/operator_e2e_outputs/verification_summary.md"
cmp -s \
  "${RUN_ONE}/operator_e2e_outputs/witness_matrix.json" \
  "${RUN_TWO}/operator_e2e_outputs/witness_matrix.json"

echo "bd-3tw7 operator E2E PASS"
echo "trace_id=${TRACE_ID}"
echo "normalized_payload=${RUN_ONE}/operator_e2e_outputs/payload.normalized.json"
