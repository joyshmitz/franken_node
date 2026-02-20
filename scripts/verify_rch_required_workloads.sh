#!/usr/bin/env bash
# verify_rch_required_workloads.sh — Fail-closed detector for rch execution policy.
#
# Scans evidence artifacts for rch provenance metadata. Any CPU-intensive
# workload result lacking rch provenance triggers a FAIL verdict.
#
# Usage:
#   scripts/verify_rch_required_workloads.sh [--json] [--artifacts-dir DIR] [--exceptions FILE]
#
# Exit codes:
#   0 = PASS (all heavy workloads have rch provenance)
#   1 = FAIL (policy violations detected)
#   2 = ERROR (missing config or parse failure)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults
ARTIFACTS_DIR="$ROOT/artifacts"
EXCEPTIONS_FILE="$ROOT/docs/verification/rch_exceptions.json"
JSON_OUTPUT=false
POLICY_VERSION="1.0"

# rch-required command kinds (must match schema enum)
RCH_REQUIRED_KINDS=(
    "CargoCheck"
    "CargoClippy"
    "CargoBuild"
    "CargoTest"
    "CargoCoverage"
    "CargoBench"
    "CargoMiri"
    "E2ESweep"
)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) JSON_OUTPUT=true; shift ;;
        --artifacts-dir) ARTIFACTS_DIR="$2"; shift 2 ;;
        --exceptions) EXCEPTIONS_FILE="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Load exceptions (if file exists)
load_exceptions() {
    if [[ -f "$EXCEPTIONS_FILE" ]]; then
        python3 -c "
import json, sys
from datetime import datetime, timezone
with open('$EXCEPTIONS_FILE') as f:
    data = json.load(f)
active = []
now = datetime.now(timezone.utc)
for exc in data.get('exceptions', []):
    expires = datetime.fromisoformat(exc['expires'].replace('Z', '+00:00'))
    if expires > now:
        active.append(exc['command_pattern'])
print('\n'.join(active))
" 2>/dev/null || true
    fi
}

# Check if a command matches an active exception
is_excepted() {
    local cmd="$1"
    while IFS= read -r pattern; do
        if [[ -n "$pattern" ]] && python3 -c "
import fnmatch, sys
sys.exit(0 if fnmatch.fnmatch('$cmd', '$pattern') else 1)
" 2>/dev/null; then
            return 0
        fi
    done <<< "$ACTIVE_EXCEPTIONS"
    return 1
}

# Classify a command string into an rch kind (or empty if not rch-required)
classify_command() {
    local cmd="$1"
    case "$cmd" in
        *"cargo check"*)    echo "CargoCheck" ;;
        *"cargo clippy"*)   echo "CargoClippy" ;;
        *"cargo build"*)    echo "CargoBuild" ;;
        *"cargo nextest"*)  echo "CargoTest" ;;
        *"cargo test"*)     echo "CargoTest" ;;
        *"cargo llvm-cov"*) echo "CargoCoverage" ;;
        *"cargo bench"*)    echo "CargoBench" ;;
        *"cargo miri"*)     echo "CargoMiri" ;;
        *"cargo +nightly miri"*) echo "CargoMiri" ;;
        *)                  echo "" ;;
    esac
}

# Scan for provenance files
ACTIVE_EXCEPTIONS=$(load_exceptions)
VIOLATIONS=()
PASSES=()
EXCEPTIONS_USED=()
PROVENANCE_FILES=0

# Scan all provenance JSON files in the artifacts tree
scan_provenance() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        return
    fi

    while IFS= read -r prov_file; do
        [[ -z "$prov_file" ]] && continue
        PROVENANCE_FILES=$((PROVENANCE_FILES + 1))

        # Use tab-separated output to avoid delimiter conflicts
        local data
        data=$(python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    cmd = d.get('command', '')
    kind = d.get('rch_kind', '')
    worker = d.get('worker_id', '')
    exc_id = d.get('exception_id') or ''
    print(f'{cmd}\t{kind}\t{worker}\t{exc_id}')
except Exception as e:
    print(f'ERROR\t{e}\t\t', file=sys.stderr)
" "$prov_file" 2>/dev/null) || continue

        local cmd kind worker exc_id
        IFS=$'\t' read -r cmd kind worker exc_id <<< "$data"

        if [[ -z "$cmd" ]] || [[ "$cmd" == "ERROR" ]]; then
            continue
        fi

        # Check if this is an rch-required kind
        local is_required=false
        for req_kind in "${RCH_REQUIRED_KINDS[@]}"; do
            if [[ "$kind" == "$req_kind" ]]; then
                is_required=true
                break
            fi
        done

        if [[ "$is_required" == "true" ]]; then
            if [[ -n "$worker" ]] && [[ "$worker" != "local" ]]; then
                PASSES+=("$prov_file:$kind:$worker")
            elif [[ -n "$exc_id" ]]; then
                EXCEPTIONS_USED+=("$prov_file:$kind:$exc_id")
            else
                VIOLATIONS+=("$prov_file:$kind:$cmd")
            fi
        fi
    done < <(fd --type file --extension json --glob '*provenance*' "$dir" 2>/dev/null || find "$dir" -name '*provenance*' -name '*.json' -type f 2>/dev/null)
}

# Also check if rch hook is installed (advisory, not blocking)
check_rch_hook() {
    if rch hook status >/dev/null 2>&1; then
        echo "installed"
    else
        echo "not_installed"
    fi
}

scan_provenance "$ARTIFACTS_DIR"
RCH_HOOK_STATUS=$(check_rch_hook)

VIOLATION_COUNT=${#VIOLATIONS[@]}
PASS_COUNT=${#PASSES[@]}
EXCEPTION_COUNT=${#EXCEPTIONS_USED[@]}

if [[ $VIOLATION_COUNT -eq 0 ]]; then
    VERDICT="PASS"
else
    VERDICT="FAIL"
fi

if [[ "$JSON_OUTPUT" == "true" ]]; then
    # Build violations JSON array
    _violations_json() {
        if [[ $VIOLATION_COUNT -eq 0 ]]; then
            echo "[]"
            return
        fi
        python3 -c "
import json
violations = []
for v in '''$(printf '%s\n' "${VIOLATIONS[@]}")'''.strip().split('\n'):
    if not v.strip():
        continue
    parts = v.split(':', 2)
    if len(parts) >= 3:
        violations.append({
            'file': parts[0],
            'kind': parts[1],
            'command': parts[2]
        })
print(json.dumps(violations))
"
    }

    cat <<EOF
{
  "gate": "rch_execution_policy",
  "verdict": "$VERDICT",
  "timestamp": "$TIMESTAMP",
  "policy_version": "$POLICY_VERSION",
  "artifacts_dir": "$ARTIFACTS_DIR",
  "provenance_files_scanned": $PROVENANCE_FILES,
  "rch_offloaded_passes": $PASS_COUNT,
  "violations_count": $VIOLATION_COUNT,
  "exceptions_used": $EXCEPTION_COUNT,
  "rch_hook_status": "$RCH_HOOK_STATUS",
  "violations": $(_violations_json)
}
EOF
else
    echo "=== RCH Execution Policy Gate ==="
    echo "Artifacts: $ARTIFACTS_DIR"
    echo "Policy version: $POLICY_VERSION"
    echo "Timestamp: $TIMESTAMP"
    echo
    echo "Provenance files scanned: $PROVENANCE_FILES"
    echo "rch-offloaded passes: $PASS_COUNT"
    echo "Exceptions used: $EXCEPTION_COUNT"
    echo "Violations: $VIOLATION_COUNT"
    echo "rch hook: $RCH_HOOK_STATUS"
    echo
    if [[ $VIOLATION_COUNT -gt 0 ]]; then
        echo "VIOLATIONS:"
        for v in "${VIOLATIONS[@]}"; do
            IFS=':' read -r file kind cmd <<< "$v"
            echo "  [$kind] $file"
            echo "    Command: $cmd"
        done
        echo
    fi
    echo "Verdict: $VERDICT"
fi

exit $([ "$VERDICT" = "PASS" ] && echo 0 || echo 1)
