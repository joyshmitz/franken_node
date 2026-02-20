#!/usr/bin/env bash
# transplant/generate_lockfile.sh — Generate transplant lockfile from snapshot
# Usage: ./transplant/generate_lockfile.sh [--source-root PATH] [--manifest FILE]
#
# Produces a deterministic SHA-256 lockfile for all files listed in the manifest.
# If no manifest is provided, discovers all files under pi_agent_rust/.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNAPSHOT_DIR="${SCRIPT_DIR}/pi_agent_rust"
OUTPUT="${SCRIPT_DIR}/TRANSPLANT_LOCKFILE.sha256"
SOURCE_ROOT="/data/projects/pi_agent_rust"
MANIFEST=""

while [ $# -gt 0 ]; do
  case "$1" in
    --source-root) SOURCE_ROOT="$2"; shift 2 ;;
    --manifest) MANIFEST="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: $0 [--source-root PATH] [--manifest FILE] [--output FILE]"
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ ! -d "$SNAPSHOT_DIR" ]; then
  echo "ERROR: Snapshot directory not found: $SNAPSHOT_DIR" >&2
  exit 2
fi

# Collect file list
if [ -n "$MANIFEST" ] && [ -f "$MANIFEST" ]; then
  FILES=$(grep -v '^#' "$MANIFEST" | grep -v '^$')
else
  FILES=$(cd "$SNAPSHOT_DIR" && fd --type file . | sed 's|^\./||' | sort)
fi

ENTRY_COUNT=$(echo "$FILES" | grep -c . || echo 0)
GENERATED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Write header
cat > "$OUTPUT" <<EOF
# TRANSPLANT LOCKFILE (sha256)
# source_root: $SOURCE_ROOT
# manifest: transplant_manifest.txt
# entries: $ENTRY_COUNT
# generated_utc: $GENERATED_UTC
EOF
echo "" >> "$OUTPUT"

# Generate hashes
while IFS= read -r relpath; do
  [ -z "$relpath" ] && continue
  filepath="${SNAPSHOT_DIR}/${relpath}"
  if [ -f "$filepath" ]; then
    hash=$(sha256sum "$filepath" | awk '{print $1}')
    echo "$hash  $relpath" >> "$OUTPUT"
  else
    echo "WARNING: File not found: $relpath" >&2
  fi
done <<< "$FILES"

echo "Generated lockfile: $OUTPUT ($ENTRY_COUNT entries)"
