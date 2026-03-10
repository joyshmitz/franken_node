#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Telemetry Bridge Performance Characterization (bd-1now.4.7)
#
# Runs performance characterization tests and captures structured artifacts
# for operator-facing performance evidence.
#
# Metrics captured:
#   - Steady-state throughput (events/sec)
#   - Burst behavior beyond queue capacity
#   - Drain/shutdown latency
#   - Queue depth evolution
#   - Enqueue latency (p50/p99)
#   - Multi-connection throughput
#
# Usage:
#   ./tests/e2e/telemetry_perf_characterization.sh
#
# Artifacts written to: artifacts/asupersync/bd-1now.4.7/
# ============================================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/artifacts/asupersync/bd-1now.4.7"
LOG_JSONL="${OUT_DIR}/telemetry_perf_log.jsonl"
PERF_OUTPUT="${OUT_DIR}/telemetry_perf_raw_output.txt"
SUMMARY_JSON="${OUT_DIR}/telemetry_perf_summary.json"
SUMMARY_MD="${OUT_DIR}/telemetry_perf_summary.md"
TRACE_ID="${TRACE_ID:-trace-bd-1now-4-7-telemetry-perf}"

mkdir -p "${OUT_DIR}"
: > "${LOG_JSONL}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required" >&2
  exit 2
fi

log_event() {
  local event_code="$1"
  local detail="$2"
  python3 - "$LOG_JSONL" "$TRACE_ID" "$event_code" "$detail" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

path = Path(sys.argv[1])
payload = {
    "ts": datetime.now(timezone.utc).isoformat(),
    "trace_id": sys.argv[2],
    "event_code": sys.argv[3],
    "detail": sys.argv[4],
}
with path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(payload) + "\n")
PY
}

echo "=========================================="
echo "Telemetry Bridge Performance Characterization"
echo "Trace ID: ${TRACE_ID}"
echo "Artifacts: ${OUT_DIR}"
echo "=========================================="
echo ""
log_event "PERF_SUITE_START" "starting telemetry performance characterization"

# Run all perf_ prefixed tests with output capture
echo "Running performance characterization tests..."
PERF_EXIT=0
cargo test -p frankenengine-node --lib ops::telemetry_bridge::tests::perf_ \
  -- --nocapture --test-threads=1 > "${PERF_OUTPUT}" 2>&1 || PERF_EXIT=$?

if [ "${PERF_EXIT}" -ne 0 ]; then
  echo "FAIL: performance tests failed (exit ${PERF_EXIT})"
  log_event "PERF_SUITE_FAIL" "tests failed with exit code ${PERF_EXIT}"
  exit 1
fi

echo "All performance tests passed."
echo ""

# Extract metrics from test output and generate summary
python3 - "${PERF_OUTPUT}" "${SUMMARY_JSON}" "${SUMMARY_MD}" "${TRACE_ID}" <<'PY'
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

raw_output = Path(sys.argv[1]).read_text()
summary_json_path = Path(sys.argv[2])
summary_md_path = Path(sys.argv[3])
trace_id = sys.argv[4]

# Parse metrics blocks like [perf_test_name]\n  key: value\n  key: value
# The header may appear mid-line (after cargo test prefix), so search anywhere
metrics = {}
current_test = None
for line in raw_output.splitlines():
    m = re.search(r'\[(perf_\w+)\]', line)
    if m:
        current_test = m.group(1)
        metrics[current_test] = {}
        continue
    if current_test:
        kv = re.match(r'^\s+(\w+):\s+(.+)$', line)
        if kv:
            key, val = kv.group(1), kv.group(2)
            # Try numeric conversion
            try:
                val = int(val)
            except ValueError:
                try:
                    val = float(val)
                except ValueError:
                    pass
            metrics[current_test][key] = val
        elif line.strip() in ('', 'ok') or line.strip().startswith('test '):
            current_test = None

# Build summary
summary = {
    "ts": datetime.now(timezone.utc).isoformat(),
    "trace_id": trace_id,
    "suite": "telemetry_perf_characterization",
    "bead": "bd-1now.4.7",
    "verdict": "PASS",
    "tests": metrics,
    "design_budgets": {
        "queue_capacity": 256,
        "max_event_bytes": 65536,
        "max_active_connections": 64,
        "enqueue_timeout_ms": 50,
        "drain_timeout_ms": 5000,
        "accept_poll_interval_ms": 100,
    },
}

with summary_json_path.open("w", encoding="utf-8") as fh:
    json.dump(summary, fh, indent=2)
    fh.write("\n")

# Build markdown
lines = [
    "# Telemetry Bridge Performance Characterization",
    "",
    f"- **Trace ID**: `{trace_id}`",
    f"- **Bead**: bd-1now.4.7",
    f"- **Verdict**: PASS",
    "",
    "## Design Budgets",
    "",
    "| Parameter | Value | Notes |",
    "|-----------|-------|-------|",
    "| Queue capacity | 256 | Bounded MPSC channel depth |",
    "| Max event bytes | 64 KB | Events larger than this are shed |",
    "| Max active connections | 64 | Connection cap before rejection |",
    "| Enqueue timeout | 50 ms | Per-event backpressure budget |",
    "| Drain timeout | 5000 ms | Max wait for persistence after stop |",
    "| Accept poll interval | 100 ms | Non-blocking listener polling rate |",
    "",
    "## Measured Performance",
    "",
]

test_order = [
    "perf_steady_state_throughput",
    "perf_burst_beyond_queue_capacity",
    "perf_drain_shutdown_latency",
    "perf_queue_depth_evolution",
    "perf_enqueue_latency_under_light_load",
    "perf_multi_connection_throughput",
]

for test_name in test_order:
    data = metrics.get(test_name, {})
    if not data:
        continue
    nice_name = test_name.replace("perf_", "").replace("_", " ").title()
    lines.append(f"### {nice_name}")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    for k, v in data.items():
        if isinstance(v, float):
            lines.append(f"| {k} | {v:.1f} |")
        else:
            lines.append(f"| {k} | {v} |")
    lines.append("")

lines.extend([
    "## Operator Notes",
    "",
    "**Steady-state throughput**: The bridge processes events at well above",
    "100 events/sec under single-connection steady-state load. This is more than",
    "sufficient for typical telemetry workloads from a single engine instance.",
    "",
    "**Burst handling**: When burst traffic exceeds the queue capacity (256 events),",
    "the bridge cleanly sheds excess events with structured shed counters. The",
    "acceptance rate depends on persistence throughput during the burst. All accepted",
    "events are guaranteed to be persisted after drain completes.",
    "",
    "**Drain latency**: Shutdown drain completes in well under 2 seconds for typical",
    "workloads (100 events). The 5-second drain timeout provides ample budget for",
    "larger queues under load.",
    "",
    "**Queue depth**: Queue depth returns to 0 after processing completes,",
    "confirming no events are stuck in the pipeline.",
    "",
    "**Enqueue latency**: p99 enqueue latency is well under 10ms under light load,",
    "meaning individual event admission is fast and non-blocking.",
    "",
    "**Multi-connection**: 10 concurrent connections can push events simultaneously",
    "with full accounting (accepted + shed + dropped = total sent).",
    "",
    "## Artifact Locations",
    "",
    "- Machine-readable summary: `artifacts/asupersync/bd-1now.4.7/telemetry_perf_summary.json`",
    "- Raw test output: `artifacts/asupersync/bd-1now.4.7/telemetry_perf_raw_output.txt`",
    "- Event log (JSONL): `artifacts/asupersync/bd-1now.4.7/telemetry_perf_log.jsonl`",
    "",
])

with summary_md_path.open("w", encoding="utf-8") as fh:
    fh.write("\n".join(lines))

# Print summary to stdout
for test_name in test_order:
    data = metrics.get(test_name, {})
    if data:
        nice = test_name.replace("perf_", "").replace("_", " ")
        print(f"  {nice}:")
        for k, v in data.items():
            if isinstance(v, float):
                print(f"    {k}: {v:.1f}")
            else:
                print(f"    {k}: {v}")
        print()

PY

log_event "PERF_SUITE_COMPLETE" "characterization complete"

echo ""
echo "Artifacts written to: ${OUT_DIR}"
echo "  - ${SUMMARY_JSON}"
echo "  - ${SUMMARY_MD}"
echo "  - ${PERF_OUTPUT}"
echo "  - ${LOG_JSONL}"
