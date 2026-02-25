#!/usr/bin/env python3
"""bd-lus verifier: scheduler lane + global bulkhead integration."""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

LANE_ROUTER = os.path.join(ROOT, "crates", "franken-node", "src", "runtime", "lane_router.rs")
BULKHEAD = os.path.join(ROOT, "crates", "franken-node", "src", "runtime", "bulkhead.rs")
CONFIG = os.path.join(ROOT, "crates", "franken-node", "src", "config.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_10_11", "bd-lus_contract.md")
TESTS = os.path.join(ROOT, "tests", "test_check_scheduler_lanes.py")

BEAD = "bd-lus"
SECTION = "10.11"


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def _checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def ok(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "passed": passed, "detail": detail})

    ok("lane_router_exists", os.path.isfile(LANE_ROUTER), LANE_ROUTER)
    ok("bulkhead_exists", os.path.isfile(BULKHEAD), BULKHEAD)
    ok("config_exists", os.path.isfile(CONFIG), CONFIG)
    ok("spec_exists", os.path.isfile(SPEC), SPEC)
    ok("tests_exists", os.path.isfile(TESTS), TESTS)

    lane_src = _read(LANE_ROUTER) if os.path.isfile(LANE_ROUTER) else ""
    bulk_src = _read(BULKHEAD) if os.path.isfile(BULKHEAD) else ""
    config_src = _read(CONFIG) if os.path.isfile(CONFIG) else ""

    lane_event_markers = [
        "LANE_ASSIGNED",
        "LANE_SATURATED",
        "BULKHEAD_OVERLOAD",
        "LANE_CONFIG_RELOAD",
    ]
    missing_events = [m for m in lane_event_markers if m not in lane_src]
    ok(
        "lane_event_codes",
        len(missing_events) == 0,
        f"{len(lane_event_markers) - len(missing_events)}/{len(lane_event_markers)} present"
        + (f" missing: {', '.join(missing_events)}" if missing_events else ""),
    )

    lane_types = [
        "ProductLane",
        "LaneRouterConfig",
        "LaneRouter",
        "LaneMetrics",
        "RouterMetricsSnapshot",
        "LaneRouterError",
    ]
    missing_types = [t for t in lane_types if t not in lane_src]
    ok(
        "lane_core_types",
        len(missing_types) == 0,
        f"{len(lane_types) - len(missing_types)}/{len(lane_types)} present"
        + (f" missing: {', '.join(missing_types)}" if missing_types else ""),
    )

    taxonomy = ["Cancel", "Timed", "Realtime", "Background"]
    missing_taxonomy = [lane for lane in taxonomy if lane not in lane_src]
    ok(
        "lane_taxonomy",
        len(missing_taxonomy) == 0,
        f"{len(taxonomy) - len(missing_taxonomy)}/{len(taxonomy)} lanes"
        + (f" missing: {', '.join(missing_taxonomy)}" if missing_taxonomy else ""),
    )

    overflow_markers = ["Reject", "EnqueueWithTimeout", "ShedOldest"]
    missing_overflow = [o for o in overflow_markers if o not in lane_src]
    ok(
        "overflow_policies",
        len(missing_overflow) == 0,
        f"{len(overflow_markers) - len(missing_overflow)}/{len(overflow_markers)} policies"
        + (f" missing: {', '.join(missing_overflow)}" if missing_overflow else ""),
    )

    ops = ["assign_operation", "complete_operation", "reload_config", "metrics_snapshot"]
    missing_ops = [op for op in ops if op not in lane_src]
    ok(
        "lane_operations",
        len(missing_ops) == 0,
        f"{len(ops) - len(missing_ops)}/{len(ops)} operations"
        + (f" missing: {', '.join(missing_ops)}" if missing_ops else ""),
    )

    ok(
        "unknown_lane_defaults_background",
        "LANE_DEFAULTED_BACKGROUND" in lane_src and "unknown_lane_default_count" in lane_src,
        "default-to-background warning path present",
    )

    metric_markers = [
        "in_flight",
        "queued",
        "completed",
        "rejected",
        "p99_queue_wait_ms",
        "total_in_flight",
        "bulkhead_rejections",
    ]
    missing_metrics = [m for m in metric_markers if m not in lane_src]
    ok(
        "metrics_contract",
        len(missing_metrics) == 0,
        f"{len(metric_markers) - len(missing_metrics)}/{len(metric_markers)} metrics"
        + (f" missing: {', '.join(missing_metrics)}" if missing_metrics else ""),
    )

    bulkhead_markers = [
        "GlobalBulkhead",
        "BulkheadPermit",
        "BulkheadError",
        "BULKHEAD_OVERLOAD",
        "try_acquire",
        "release",
        "reload_limits",
    ]
    missing_bulk = [m for m in bulkhead_markers if m not in bulk_src]
    ok(
        "bulkhead_surface",
        len(missing_bulk) == 0,
        f"{len(bulkhead_markers) - len(missing_bulk)}/{len(bulkhead_markers)} markers"
        + (f" missing: {', '.join(missing_bulk)}" if missing_bulk else ""),
    )

    config_markers = [
        "pub struct RuntimeConfig",
        "pub struct RuntimeLaneConfig",
        "pub enum LaneOverflowPolicy",
        "remote_max_in_flight",
        "bulkhead_retry_after_ms",
        "FRANKEN_NODE_RUNTIME_REMOTE_MAX_IN_FLIGHT",
        "FRANKEN_NODE_RUNTIME_BULKHEAD_RETRY_AFTER_MS",
    ]
    missing_cfg = [m for m in config_markers if m not in config_src]
    ok(
        "runtime_config_contract",
        len(missing_cfg) == 0,
        f"{len(config_markers) - len(missing_cfg)}/{len(config_markers)} markers"
        + (f" missing: {', '.join(missing_cfg)}" if missing_cfg else ""),
    )

    # Coverage expectations inside module tests.
    lane_test_count = len(re.findall(r"#\[test\]", lane_src))
    bulkhead_test_count = len(re.findall(r"#\[test\]", bulk_src))
    ok("lane_test_count", lane_test_count >= 10, f"{lane_test_count} tests (>=10)")
    ok("bulkhead_test_count", bulkhead_test_count >= 8, f"{bulkhead_test_count} tests (>=8)")

    # Mixed workload integration scenario should be explicitly present.
    ok(
        "mixed_workload_integration_test",
        "integration_mixed_100_operations_respects_global_cap" in lane_src,
        "100-op integration simulation present",
    )

    # Ensure checker tests reference this bead and script.
    if os.path.isfile(TESTS):
        test_src = _read(TESTS)
    else:
        test_src = ""
    ok(
        "tests_reference_script",
        "check_scheduler_lanes.py" in test_src and "bd-lus" in test_src,
        "test file references script + bead",
    )

    return checks


def self_test() -> bool:
    checks = _checks()
    assert len(checks) >= 16, f"expected >=16 checks, got {len(checks)}"
    assert all("check" in c and "passed" in c for c in checks)
    print(f"self_test: {len(checks)} checks validated", file=sys.stderr)
    return True


def main() -> int:
    logger = configure_test_logging("check_scheduler_lanes")
    if "--self-test" in sys.argv:
        self_test()
        return 0

    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    total = len(checks)
    verdict = "PASS" if passed == total else "FAIL"

    payload = {
        "bead_id": BEAD,
        "section": SECTION,
        "gate_script": os.path.basename(__file__),
        "checks_passed": passed,
        "checks_total": total,
        "verdict": verdict,
        "checks": checks,
    }

    if "--json" in sys.argv:
        print(json.dumps(payload, indent=2))
    else:
        print(f"{BEAD}: {verdict} ({passed}/{total})")
        for c in checks:
            mark = "PASS" if c["passed"] else "FAIL"
            print(f"  [{mark}] {c['check']}: {c['detail']}")

    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
