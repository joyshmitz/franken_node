#!/usr/bin/env bash
# transplant/verify_lockfile.sh — Verify transplant snapshot against lockfile
# Usage: ./transplant/verify_lockfile.sh [--json] [--quiet]
#
# Exit codes:
#   0 = PASS (all entries verified, no extras)
#   1 = FAIL (mismatches, missing files, or extras detected)
#   2 = ERROR (lockfile not found, parse error, etc.)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCKFILE="${SCRIPT_DIR}/TRANSPLANT_LOCKFILE.sha256"
SNAPSHOT_DIR="${SCRIPT_DIR}/pi_agent_rust"

JSON_OUTPUT=false
QUIET=false

for arg in "$@"; do
  case "$arg" in
    --json) JSON_OUTPUT=true ;;
    --quiet) QUIET=true ;;
    --help|-h)
      echo "Usage: $0 [--json] [--quiet]"
      echo "  --json   Output structured JSON report"
      echo "  --quiet  Suppress progress output (exit code only)"
      exit 0
      ;;
  esac
done

# Validate prerequisites
if [ ! -f "$LOCKFILE" ]; then
  echo "ERROR: Lockfile not found: $LOCKFILE" >&2
  exit 2
fi
if [ ! -d "$SNAPSHOT_DIR" ]; then
  echo "ERROR: Snapshot directory not found: $SNAPSHOT_DIR" >&2
  exit 2
fi

# Parse header
EXPECTED_COUNT=$(grep '^# entries:' "$LOCKFILE" | awk '{print $3}')
SOURCE_ROOT=$(grep '^# source_root:' "$LOCKFILE" | sed 's/^# source_root: //')
GENERATED_UTC=$(grep '^# generated_utc:' "$LOCKFILE" | sed 's/^# generated_utc: //')

# Count actual entries
ACTUAL_COUNT=$(grep -v '^#' "$LOCKFILE" | grep -v '^$' | wc -l | tr -d ' ')

if [ "$EXPECTED_COUNT" != "$ACTUAL_COUNT" ]; then
  echo "FAIL:COUNT — header says $EXPECTED_COUNT entries but found $ACTUAL_COUNT" >&2
  exit 1
fi

# Verify each entry
PASS=0
MISMATCH=0
MISSING=0
MISMATCH_FILES=""
MISSING_FILES=""

while IFS='  ' read -r expected_hash relpath; do
  [ -z "$expected_hash" ] && continue
  filepath="${SNAPSHOT_DIR}/${relpath}"

  if [ ! -f "$filepath" ]; then
    MISSING=$((MISSING + 1))
    MISSING_FILES="${MISSING_FILES}${relpath}\n"
    $QUIET || echo "MISSING: $relpath" >&2
    continue
  fi

  actual_hash=$(sha256sum "$filepath" | awk '{print $1}')
  if [ "$actual_hash" = "$expected_hash" ]; then
    PASS=$((PASS + 1))
  else
    MISMATCH=$((MISMATCH + 1))
    MISMATCH_FILES="${MISMATCH_FILES}${relpath}\n"
    $QUIET || echo "MISMATCH: $relpath (expected ${expected_hash:0:16}... got ${actual_hash:0:16}...)" >&2
  fi
done < <(grep -v '^#' "$LOCKFILE" | grep -v '^$')

# Scan for extra files not in lockfile
LOCKFILE_PATHS=$(grep -v '^#' "$LOCKFILE" | grep -v '^$' | awk '{print $2}' | sort)
SNAPSHOT_PATHS=$(cd "$SNAPSHOT_DIR" && fd --type file . | sed 's|^\./||' | sort)
EXTRA_FILES=$(comm -13 <(echo "$LOCKFILE_PATHS") <(echo "$SNAPSHOT_PATHS") | grep -v '^$' || true)
if [ -z "$EXTRA_FILES" ]; then
  EXTRA_COUNT=0
else
  EXTRA_COUNT=$(echo "$EXTRA_FILES" | wc -l | tr -d ' ')
fi

# Determine verdict
VERDICT="PASS"
if [ "$MISMATCH" -gt 0 ]; then VERDICT="FAIL:MISMATCH"; fi
if [ "$MISSING" -gt 0 ]; then VERDICT="FAIL:MISSING"; fi
if [ "$EXTRA_COUNT" -gt 0 ] && [ -n "$EXTRA_FILES" ]; then VERDICT="FAIL:EXTRA"; fi

# Output
if $JSON_OUTPUT; then
  cat <<ENDJSON
{
  "verdict": "$VERDICT",
  "lockfile": "$(basename "$LOCKFILE")",
  "snapshot_dir": "$(basename "$SNAPSHOT_DIR")",
  "source_root": "$SOURCE_ROOT",
  "generated_utc": "$GENERATED_UTC",
  "expected_entries": $EXPECTED_COUNT,
  "verified_ok": $PASS,
  "mismatched": $MISMATCH,
  "missing": $MISSING,
  "extra": $EXTRA_COUNT,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
ENDJSON
else
  echo ""
  echo "=== Transplant Lockfile Verification ==="
  echo "Lockfile:    $(basename "$LOCKFILE")"
  echo "Snapshot:    $(basename "$SNAPSHOT_DIR")/"
  echo "Source:      $SOURCE_ROOT"
  echo "Generated:   $GENERATED_UTC"
  echo ""
  echo "Entries:     $EXPECTED_COUNT"
  echo "Verified OK: $PASS"
  echo "Mismatched:  $MISMATCH"
  echo "Missing:     $MISSING"
  echo "Extra:       $EXTRA_COUNT"
  echo ""
  echo "Verdict:     $VERDICT"
fi

if [ "$VERDICT" = "PASS" ]; then
  exit 0
else
  exit 1
fi
