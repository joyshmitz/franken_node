#!/bin/bash
# Helper script to update lane scheduler golden artifacts
# Usage: ./scripts/update_lane_scheduler_goldens.sh [test_name]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Set UPDATE_GOLDENS environment variable
export UPDATE_GOLDENS=1

if [ $# -eq 0 ]; then
    echo "Updating all lane scheduler golden artifacts..."
    rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_cc3_test cargo test lane_scheduler_golden --lib
else
    echo "Updating specific test: $1"
    rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_cc3_test cargo test "$1" --lib
fi

echo ""
echo "Golden files updated. Review changes with:"
echo "  git diff tests/golden/lane_scheduler/"
echo ""
echo "To commit approved changes:"
echo "  git add tests/golden/lane_scheduler/"
echo "  git commit -m 'Update lane scheduler golden artifacts: [describe reason]'"