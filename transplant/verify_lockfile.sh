#!/usr/bin/env bash
# transplant/verify_lockfile.sh — Verify transplant snapshot against lockfile.
#
# Usage:
#   ./transplant/verify_lockfile.sh \
#     [--json] \
#     [--quiet] \
#     [--lockfile PATH] \
#     [--snapshot-dir PATH]
#
# Exit codes:
#   0 = PASS (all entries verified, no extras)
#   1 = FAIL (mismatches, missing files, extras, parse/count problems)
#   2 = ERROR (lockfile/snapshot missing, invalid usage)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCKFILE="${SCRIPT_DIR}/TRANSPLANT_LOCKFILE.sha256"
SNAPSHOT_DIR="${SCRIPT_DIR}/pi_agent_rust"

JSON_OUTPUT=false
QUIET=false

usage() {
  cat <<'USAGE'
Usage: verify_lockfile.sh [options]
  --json                 Output structured JSON report.
  --quiet                Suppress mismatch/missing/extra line diagnostics.
  --lockfile PATH        Override lockfile path.
  --snapshot-dir PATH    Override snapshot directory.
  --help, -h             Show this help.
USAGE
}

discover_snapshot_files() {
  if command -v fd >/dev/null 2>&1; then
    fd --type file .
  else
    find . -type f -print
  fi
}

to_json_array() {
  if [ "$#" -eq 0 ]; then
    echo "[]"
    return
  fi
  printf '%s\n' "$@" \
    | python3 -c 'import json,sys; print(json.dumps([line.rstrip("\n") for line in sys.stdin if line.strip()]))'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --json)
      JSON_OUTPUT=true
      shift
      ;;
    --quiet)
      QUIET=true
      shift
      ;;
    --lockfile)
      LOCKFILE="$2"
      shift 2
      ;;
    --snapshot-dir)
      SNAPSHOT_DIR="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ ! -f "$LOCKFILE" ]; then
  echo "ERROR: Lockfile not found: $LOCKFILE" >&2
  exit 2
fi
if [ ! -d "$SNAPSHOT_DIR" ]; then
  echo "ERROR: Snapshot directory not found: $SNAPSHOT_DIR" >&2
  exit 2
fi

EXPECTED_COUNT="$(awk '/^# entries:/{print $3; exit}' "$LOCKFILE")"
SOURCE_ROOT="$(awk -F': ' '/^# source_root:/{print $2; exit}' "$LOCKFILE")"
GENERATED_UTC="$(awk -F': ' '/^# generated_utc:/{print $2; exit}' "$LOCKFILE")"

if ! [[ "$EXPECTED_COUNT" =~ ^[0-9]+$ ]]; then
  echo "ERROR: Invalid or missing '# entries:' header in $LOCKFILE" >&2
  exit 2
fi

declare -A LOCKFILE_HASHES=()
declare -a LOCKFILE_PATHS=()
declare -a PARSE_ERRORS=()

while IFS= read -r line; do
  [[ -z "$line" || "$line" == \#* ]] && continue
  if [[ "$line" =~ ^([0-9a-f]{64})[[:space:]][[:space:]](.+)$ ]]; then
    expected_hash="${BASH_REMATCH[1]}"
    relpath="${BASH_REMATCH[2]}"
    if [ -n "${LOCKFILE_HASHES[$relpath]+x}" ]; then
      PARSE_ERRORS+=("duplicate-path:$relpath")
      continue
    fi
    LOCKFILE_HASHES["$relpath"]="$expected_hash"
    LOCKFILE_PATHS+=("$relpath")
  else
    PARSE_ERRORS+=("$line")
  fi
done < "$LOCKFILE"

ACTUAL_COUNT="${#LOCKFILE_PATHS[@]}"
COUNT_MISMATCH=0
if [ "$EXPECTED_COUNT" -ne "$ACTUAL_COUNT" ]; then
  COUNT_MISMATCH=1
  $QUIET || echo "COUNT_MISMATCH: header=$EXPECTED_COUNT entries=$ACTUAL_COUNT" >&2
fi

declare -a MISMATCH_FILES=()
declare -a MISSING_FILES=()
declare -a EXTRA_FILES=()
PASS=0

for relpath in "${LOCKFILE_PATHS[@]}"; do
  filepath="${SNAPSHOT_DIR}/${relpath}"
  if [ ! -f "$filepath" ]; then
    MISSING_FILES+=("$relpath")
    $QUIET || echo "MISSING: $relpath" >&2
    continue
  fi

  expected_hash="${LOCKFILE_HASHES[$relpath]}"
  actual_hash="$(sha256sum "$filepath" | awk '{print $1}')"
  if [ "$actual_hash" = "$expected_hash" ]; then
    PASS=$((PASS + 1))
  else
    MISMATCH_FILES+=("$relpath")
    $QUIET || echo "MISMATCH: $relpath (expected ${expected_hash:0:16}... got ${actual_hash:0:16}...)" >&2
  fi
done

while IFS= read -r relpath; do
  [ -z "$relpath" ] && continue
  if [ -z "${LOCKFILE_HASHES[$relpath]+x}" ]; then
    EXTRA_FILES+=("$relpath")
    $QUIET || echo "EXTRA: $relpath" >&2
  fi
done < <(
  cd "$SNAPSHOT_DIR"
  discover_snapshot_files \
    | sed -e 's|^\./||' -e 's|^/||' -e 's/\r$//' \
    | LC_ALL=C sort -u
)

MISMATCH_COUNT="${#MISMATCH_FILES[@]}"
MISSING_COUNT="${#MISSING_FILES[@]}"
EXTRA_COUNT="${#EXTRA_FILES[@]}"
PARSE_ERROR_COUNT="${#PARSE_ERRORS[@]}"

declare -a FAILING_CATEGORIES=()
if [ "$PARSE_ERROR_COUNT" -gt 0 ]; then FAILING_CATEGORIES+=("parse"); fi
if [ "$COUNT_MISMATCH" -eq 1 ]; then FAILING_CATEGORIES+=("count"); fi
if [ "$MISMATCH_COUNT" -gt 0 ]; then FAILING_CATEGORIES+=("mismatch"); fi
if [ "$MISSING_COUNT" -gt 0 ]; then FAILING_CATEGORIES+=("missing"); fi
if [ "$EXTRA_COUNT" -gt 0 ]; then FAILING_CATEGORIES+=("extra"); fi

VERDICT="PASS"
if [ "$PARSE_ERROR_COUNT" -gt 0 ]; then
  VERDICT="FAIL:PARSE"
elif [ "$COUNT_MISMATCH" -eq 1 ]; then
  VERDICT="FAIL:COUNT"
elif [ "$MISMATCH_COUNT" -gt 0 ]; then
  VERDICT="FAIL:MISMATCH"
elif [ "$MISSING_COUNT" -gt 0 ]; then
  VERDICT="FAIL:MISSING"
elif [ "$EXTRA_COUNT" -gt 0 ]; then
  VERDICT="FAIL:EXTRA"
fi

TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if $JSON_OUTPUT; then
  mismatch_json="$(to_json_array "${MISMATCH_FILES[@]}")"
  missing_json="$(to_json_array "${MISSING_FILES[@]}")"
  extra_json="$(to_json_array "${EXTRA_FILES[@]}")"
  parse_json="$(to_json_array "${PARSE_ERRORS[@]}")"
  categories_json="$(to_json_array "${FAILING_CATEGORIES[@]}")"

  cat <<ENDJSON
{
  "verdict": "$VERDICT",
  "lockfile": "$(basename "$LOCKFILE")",
  "snapshot_dir": "$SNAPSHOT_DIR",
  "source_root": "$SOURCE_ROOT",
  "generated_utc": "$GENERATED_UTC",
  "expected_entries": $EXPECTED_COUNT,
  "parsed_entries": $ACTUAL_COUNT,
  "verified_ok": $PASS,
  "mismatched": $MISMATCH_COUNT,
  "missing": $MISSING_COUNT,
  "extra": $EXTRA_COUNT,
  "parse_errors": $PARSE_ERROR_COUNT,
  "count_mismatch": $COUNT_MISMATCH,
  "failing_categories": $categories_json,
  "details": {
    "mismatched_files": $mismatch_json,
    "missing_files": $missing_json,
    "extra_files": $extra_json,
    "parse_error_lines": $parse_json
  },
  "timestamp": "$TIMESTAMP"
}
ENDJSON
else
  echo ""
  echo "=== Transplant Lockfile Verification ==="
  echo "Lockfile:       $(basename "$LOCKFILE")"
  echo "Snapshot dir:   $SNAPSHOT_DIR"
  echo "Source root:    $SOURCE_ROOT"
  echo "Generated UTC:  $GENERATED_UTC"
  echo ""
  echo "Expected count: $EXPECTED_COUNT"
  echo "Parsed entries: $ACTUAL_COUNT"
  echo "Verified OK:    $PASS"
  echo "Mismatched:     $MISMATCH_COUNT"
  echo "Missing:        $MISSING_COUNT"
  echo "Extra:          $EXTRA_COUNT"
  echo "Parse errors:   $PARSE_ERROR_COUNT"
  echo ""
  if [ "${#FAILING_CATEGORIES[@]}" -gt 0 ]; then
    echo "Failing categories: ${FAILING_CATEGORIES[*]}"
  else
    echo "Failing categories: none"
  fi
  echo "Verdict:        $VERDICT"
fi

if [ "$VERDICT" = "PASS" ]; then
  exit 0
fi
exit 1
