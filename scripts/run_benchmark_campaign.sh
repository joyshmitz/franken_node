#!/usr/bin/env bash
set -euo pipefail

BASELINE="fixtures/benchmarks/campaign_results_baseline.json"
CANDIDATE="fixtures/benchmarks/campaign_results_candidate.json"
OUTPUT="artifacts/section_10_9/bd-f5d/campaign_run.json"
DIFF_OUTPUT="artifacts/section_10_9/bd-f5d/diff_report.json"
REPORT_OUTPUT="artifacts/section_10_9/bd-f5d/public_report.md"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --baseline) BASELINE="$2"; shift 2 ;;
    --candidate) CANDIDATE="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --diff-output) DIFF_OUTPUT="$2"; shift 2 ;;
    --report-output) REPORT_OUTPUT="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$(dirname "$OUTPUT")"
mkdir -p "$(dirname "$DIFF_OUTPUT")"
mkdir -p "$(dirname "$REPORT_OUTPUT")"

cp "$CANDIDATE" "$OUTPUT"

python3 - "$BASELINE" "$CANDIDATE" "$DIFF_OUTPUT" "$REPORT_OUTPUT" <<'PY'
import json
import pathlib
import sys

baseline = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
candidate = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
diff_path = pathlib.Path(sys.argv[3])
report_path = pathlib.Path(sys.argv[4])

base_map = {w["name"]: w["metrics"]["franken_node"] for w in baseline["workloads"]}
cand_map = {w["name"]: w["metrics"]["franken_node"] for w in candidate["workloads"]}

rows = []
for name, cur in sorted(cand_map.items()):
    prev = base_map[name]
    prev_p95 = prev["latency_ms"]["p95"]
    cur_p95 = cur["latency_ms"]["p95"]
    prev_thr = prev["throughput_rps"]
    cur_thr = cur["throughput_rps"]
    rows.append(
        {
            "workload": name,
            "p95_delta_pct": round(((cur_p95 - prev_p95) / prev_p95) * 100.0, 3),
            "throughput_delta_pct": round(((cur_thr - prev_thr) / prev_thr) * 100.0, 3),
        }
    )

targets = candidate["targets"]
summary = {
    "compatibility_target_met": targets["compatibility_pct"] >= 95.0,
    "migration_velocity_target_met": targets["migration_velocity_x"] >= 3.0,
    "compromise_reduction_target_met": targets["compromise_reduction_x"] >= 10.0,
}

payload = {
    "campaign_id": candidate["campaign_id"],
    "baseline_label": baseline["run_label"],
    "candidate_label": candidate["run_label"],
    "rows": rows,
    "summary": summary,
}

diff_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

lines = [
    "# Public Benchmark Campaign Report",
    "",
    "| Workload | p95 Latency Delta % (franken_node) | Throughput Delta % (franken_node) |",
    "|---|---:|---:|",
]
for row in rows:
    lines.append(f"| {row['workload']} | {row['p95_delta_pct']} | {row['throughput_delta_pct']} |")

lines.extend(
    [
        "",
        "## Category-Defining Targets",
        f"- Compatibility >=95%: {'PASS' if summary['compatibility_target_met'] else 'FAIL'}",
        f"- Migration velocity >=3x: {'PASS' if summary['migration_velocity_target_met'] else 'FAIL'}",
        f"- Compromise reduction >=10x: {'PASS' if summary['compromise_reduction_target_met'] else 'FAIL'}",
    ]
)
report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

echo "campaign output: $OUTPUT"
echo "diff output: $DIFF_OUTPUT"
echo "report output: $REPORT_OUTPUT"
