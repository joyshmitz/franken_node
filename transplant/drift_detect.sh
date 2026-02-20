#!/usr/bin/env bash
# transplant/drift_detect.sh — Detect drift between transplant snapshot and upstream source
#
# Usage: ./transplant/drift_detect.sh [--json] [--quiet] [--source PATH]
#
# Drift categories:
#   CONTENT_DRIFT  — File exists in both but content differs
#   MISSING_LOCAL  — File in lockfile but missing from local snapshot
#   MISSING_SOURCE — File in lockfile but missing from upstream source
#   EXTRA_LOCAL    — File in local snapshot but not in lockfile
#   EXTRA_SOURCE   — File in upstream source (matching paths) but not in lockfile
#
# Exit codes:
#   0 = NO_DRIFT (snapshot matches both lockfile and upstream)
#   1 = DRIFT_DETECTED (one or more findings)
#   2 = ERROR (missing files, parse error, etc.)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCKFILE="${SCRIPT_DIR}/TRANSPLANT_LOCKFILE.sha256"
SNAPSHOT_DIR="${SCRIPT_DIR}/pi_agent_rust"
SOURCE_ROOT="/data/projects/pi_agent_rust"

JSON_OUTPUT=false
QUIET=false

while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON_OUTPUT=true; shift ;;
    --quiet) QUIET=true; shift ;;
    --source) SOURCE_ROOT="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: $0 [--json] [--quiet] [--source PATH]"
      echo "  --json    Output structured JSON report"
      echo "  --quiet   Suppress progress output (exit code only)"
      echo "  --source  Override upstream source path (default: /data/projects/pi_agent_rust)"
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

# Validate prerequisites
for path in "$LOCKFILE" "$SNAPSHOT_DIR" "$SOURCE_ROOT"; do
  if [ ! -e "$path" ]; then
    echo "ERROR: Not found: $path" >&2
    exit 2
  fi
done

# Parse lockfile entries
declare -A LOCKFILE_HASHES
LOCKFILE_PATHS=()
while IFS='  ' read -r hash relpath; do
  [ -z "$hash" ] && continue
  LOCKFILE_HASHES["$relpath"]="$hash"
  LOCKFILE_PATHS+=("$relpath")
done < <(grep -v '^#' "$LOCKFILE" | grep -v '^$')

TOTAL_ENTRIES=${#LOCKFILE_PATHS[@]}
CONTENT_DRIFT=()
MISSING_LOCAL=()
MISSING_SOURCE=()

# Check each lockfile entry
for relpath in "${LOCKFILE_PATHS[@]}"; do
  local_file="${SNAPSHOT_DIR}/${relpath}"
  source_file="${SOURCE_ROOT}/${relpath}"
  expected_hash="${LOCKFILE_HASHES[$relpath]}"

  # Check local snapshot
  if [ ! -f "$local_file" ]; then
    MISSING_LOCAL+=("$relpath")
    $QUIET || echo "MISSING_LOCAL: $relpath" >&2
    continue
  fi

  # Check upstream source
  if [ ! -f "$source_file" ]; then
    MISSING_SOURCE+=("$relpath")
    $QUIET || echo "MISSING_SOURCE: $relpath" >&2
    continue
  fi

  # Compare content between local and upstream
  local_hash=$(sha256sum "$local_file" | awk '{print $1}')
  source_hash=$(sha256sum "$source_file" | awk '{print $1}')

  if [ "$local_hash" != "$source_hash" ]; then
    CONTENT_DRIFT+=("$relpath")
    $QUIET || echo "CONTENT_DRIFT: $relpath (local=${local_hash:0:12}... source=${source_hash:0:12}...)" >&2
  fi
done

# Scan for extra local files
EXTRA_LOCAL=()
while IFS= read -r relpath; do
  [ -z "$relpath" ] && continue
  if [ -z "${LOCKFILE_HASHES[$relpath]+x}" ]; then
    EXTRA_LOCAL+=("$relpath")
    $QUIET || echo "EXTRA_LOCAL: $relpath" >&2
  fi
done < <(cd "$SNAPSHOT_DIR" && fd --type file . | sed 's|^\./||' | sort)

# Determine verdict
TOTAL_FINDINGS=$(( ${#CONTENT_DRIFT[@]} + ${#MISSING_LOCAL[@]} + ${#MISSING_SOURCE[@]} + ${#EXTRA_LOCAL[@]} ))
if [ "$TOTAL_FINDINGS" -eq 0 ]; then
  VERDICT="NO_DRIFT"
else
  VERDICT="DRIFT_DETECTED"
fi

# Output
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

if $JSON_OUTPUT; then
  # Build JSON arrays safely
  _to_json_array() {
    if [ $# -eq 0 ]; then echo "[]"; return; fi
    printf '%s\n' "$@" | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))"
  }
  content_json=$(_to_json_array "${CONTENT_DRIFT[@]+"${CONTENT_DRIFT[@]}"}")
  missing_local_json=$(_to_json_array "${MISSING_LOCAL[@]+"${MISSING_LOCAL[@]}"}")
  missing_source_json=$(_to_json_array "${MISSING_SOURCE[@]+"${MISSING_SOURCE[@]}"}")
  extra_local_json=$(_to_json_array "${EXTRA_LOCAL[@]+"${EXTRA_LOCAL[@]}"}")

  cat <<ENDJSON
{
  "verdict": "$VERDICT",
  "timestamp": "$TIMESTAMP",
  "lockfile_entries": $TOTAL_ENTRIES,
  "source_root": "$SOURCE_ROOT",
  "snapshot_dir": "$(basename "$SNAPSHOT_DIR")",
  "findings": {
    "total": $TOTAL_FINDINGS,
    "content_drift": ${#CONTENT_DRIFT[@]},
    "missing_local": ${#MISSING_LOCAL[@]},
    "missing_source": ${#MISSING_SOURCE[@]},
    "extra_local": ${#EXTRA_LOCAL[@]}
  },
  "details": {
    "content_drift": $content_json,
    "missing_local": $missing_local_json,
    "missing_source": $missing_source_json,
    "extra_local": $extra_local_json
  }
}
ENDJSON
else
  echo ""
  echo "=== Transplant Drift Detection ==="
  echo "Lockfile entries: $TOTAL_ENTRIES"
  echo "Source:           $SOURCE_ROOT"
  echo "Snapshot:         $(basename "$SNAPSHOT_DIR")/"
  echo "Timestamp:        $TIMESTAMP"
  echo ""
  echo "Findings:"
  echo "  Content drift:   ${#CONTENT_DRIFT[@]}"
  echo "  Missing (local): ${#MISSING_LOCAL[@]}"
  echo "  Missing (source):${#MISSING_SOURCE[@]}"
  echo "  Extra (local):   ${#EXTRA_LOCAL[@]}"
  echo "  Total:           $TOTAL_FINDINGS"
  echo ""
  echo "Verdict:           $VERDICT"

  if [ "${#CONTENT_DRIFT[@]}" -gt 0 ]; then
    echo ""
    echo "Content drift files:"
    for f in "${CONTENT_DRIFT[@]}"; do echo "  - $f"; done
  fi
fi

if [ "$VERDICT" = "NO_DRIFT" ]; then
  exit 0
else
  exit 1
fi
