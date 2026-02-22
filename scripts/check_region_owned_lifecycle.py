#!/usr/bin/env python3
"""bd-2tdi gate: Region-Owned Lifecycle Orchestration (Section 10.15).

Validates that the region_ownership module implements HRI-2 region-owned
execution trees with quiescence guarantees for connector lifecycle.

Usage:
    python scripts/check_region_owned_lifecycle.py           # human-readable
    python scripts/check_region_owned_lifecycle.py --json    # JSON output
    python scripts/check_region_owned_lifecycle.py --self-test  # self-test
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BEAD = "bd-2tdi"
SECTION = "10.15"
TITLE = "Region-Owned Lifecycle Orchestration"

IMPL_PATH = ROOT / "crates" / "franken-node" / "src" / "connector" / "region_ownership.rs"
LIFECYCLE_PATH = ROOT / "crates" / "franken-node" / "src" / "connector" / "lifecycle.rs"
SPEC_PATH = ROOT / "docs" / "specs" / "section_10_15" / "bd-2tdi_contract.md"
EVIDENCE_PATH = ROOT / "artifacts" / "section_10_15" / "bd-2tdi" / "verification_evidence.json"
SUMMARY_PATH = ROOT / "artifacts" / "section_10_15" / "bd-2tdi" / "verification_summary.md"
TEST_PATH = ROOT / "tests" / "test_check_region_owned_lifecycle.py"

EVENT_CODES = ["RGN-001", "RGN-002", "RGN-003", "RGN-004", "RGN-005"]

INVARIANTS = [
    "INV-RGN-QUIESCENCE",
    "INV-RGN-NO-OUTLIVE",
    "INV-RGN-HIERARCHY",
    "INV-RGN-DETERMINISTIC",
]

REQUIRED_TYPES = [
    "RegionId",
    "RegionKind",
    "Region",
    "CloseResult",
    "RegionEvent",
    "RegionError",
    "RegionTask",
    "TaskState",
]


def _file_text(path: Path) -> str | None:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return None


def _checks():
    results = []

    def ok(name, passed, detail=""):
        results.append({"check": name, "passed": passed, "detail": detail})

    # 1. Implementation file exists
    impl_text = _file_text(IMPL_PATH)
    ok("impl_exists", impl_text is not None,
       str(IMPL_PATH.relative_to(ROOT)) if impl_text else "region_ownership.rs missing")

    # 2. Event codes present
    if impl_text:
        for code in EVENT_CODES:
            found = f'"{code}"' in impl_text
            ok(f"event_code:{code}", found,
               f"{code} found" if found else f"{code} missing")
    else:
        for code in EVENT_CODES:
            ok(f"event_code:{code}", False, "impl missing")

    # 3. Required types present
    if impl_text:
        for typ in REQUIRED_TYPES:
            found = typ in impl_text
            ok(f"type:{typ}", found,
               f"{typ} defined" if found else f"{typ} missing")
    else:
        for typ in REQUIRED_TYPES:
            ok(f"type:{typ}", False, "impl missing")

    # 4. Region hierarchy builder
    if impl_text:
        has_hierarchy = "build_lifecycle_hierarchy" in impl_text
        ok("hierarchy_builder", has_hierarchy,
           "build_lifecycle_hierarchy found" if has_hierarchy else "missing")
    else:
        ok("hierarchy_builder", False, "impl missing")

    # 5. Quiescence trace generator
    if impl_text:
        has_trace = "generate_quiescence_trace" in impl_text
        ok("trace_generator", has_trace,
           "generate_quiescence_trace found" if has_trace else "missing")
    else:
        ok("trace_generator", False, "impl missing")

    # 6. Region close method
    if impl_text:
        has_close = "fn close(" in impl_text
        ok("region_close", has_close,
           "close() method found" if has_close else "close() missing")
    else:
        ok("region_close", False, "impl missing")

    # 7. Region open_child method
    if impl_text:
        has_child = "fn open_child(" in impl_text
        ok("region_open_child", has_child,
           "open_child() method found" if has_child else "open_child() missing")
    else:
        ok("region_open_child", False, "impl missing")

    # 8. Is quiescent check
    if impl_text:
        has_quiescent = "fn is_quiescent" in impl_text
        ok("is_quiescent", has_quiescent,
           "is_quiescent() found" if has_quiescent else "is_quiescent() missing")
    else:
        ok("is_quiescent", False, "impl missing")

    # 9. Lifecycle FSM exists
    lifecycle_text = _file_text(LIFECYCLE_PATH)
    ok("lifecycle_exists", lifecycle_text is not None,
       "lifecycle.rs exists" if lifecycle_text else "lifecycle.rs missing")

    # 10. Lifecycle has ConnectorState
    if lifecycle_text:
        has_state = "ConnectorState" in lifecycle_text
        ok("lifecycle_connector_state", has_state,
           "ConnectorState found" if has_state else "ConnectorState missing")
    else:
        ok("lifecycle_connector_state", False, "lifecycle.rs missing")

    # 11. Region kinds match lifecycle phases
    if impl_text:
        kinds = ["ConnectorLifecycle", "HealthGate", "Rollout", "Fencing"]
        all_present = all(k in impl_text for k in kinds)
        ok("region_kinds", all_present,
           f"all {len(kinds)} region kinds present" if all_present else "missing region kinds")
    else:
        ok("region_kinds", False, "impl missing")

    # 12. Error codes present
    if impl_text:
        errors = ["RGN_ALREADY_CLOSED", "RGN_CHILD_STILL_OPEN", "RGN_TASK_NOT_FOUND"]
        found = [e for e in errors if e in impl_text]
        ok("error_codes", len(found) == len(errors),
           f"{len(found)}/{len(errors)} error codes" if found else "missing")
    else:
        ok("error_codes", False, "impl missing")

    # 13. Rust tests present
    if impl_text:
        test_count = impl_text.count("#[test]")
        ok("rust_tests", test_count >= 8,
           f"{test_count} tests found (>=8 required)")
    else:
        ok("rust_tests", False, "impl missing")

    # 14. Spec contract exists
    spec_text = _file_text(SPEC_PATH)
    ok("spec_exists", spec_text is not None,
       str(SPEC_PATH.relative_to(ROOT)) if spec_text else "spec missing")

    # 15. Spec references invariants
    if spec_text:
        for inv in INVARIANTS:
            found = inv in spec_text
            ok(f"spec_invariant:{inv}", found,
               f"{inv} in spec" if found else f"{inv} missing from spec")
    else:
        for inv in INVARIANTS:
            ok(f"spec_invariant:{inv}", False, "spec missing")

    # 16. Evidence exists
    evidence_text = _file_text(EVIDENCE_PATH)
    ok("evidence_exists", evidence_text is not None,
       "evidence JSON exists" if evidence_text else "evidence missing")

    # 17. Evidence valid JSON
    if evidence_text:
        try:
            evidence_data = json.loads(evidence_text)
            ok("evidence_valid", True, "valid JSON")
        except json.JSONDecodeError:
            ok("evidence_valid", False, "invalid JSON")
            evidence_data = None
    else:
        ok("evidence_valid", False, "evidence missing")

    # 18. Evidence verdict PASS
    if evidence_text:
        try:
            evidence_data = json.loads(evidence_text)
            verdict = evidence_data.get("verdict")
            ok("evidence_verdict", verdict == "PASS",
               f"verdict={verdict}" if verdict else "no verdict")
        except json.JSONDecodeError:
            ok("evidence_verdict", False, "invalid JSON")
    else:
        ok("evidence_verdict", False, "evidence missing")

    # 19. Summary exists
    ok("summary_exists", _file_text(SUMMARY_PATH) is not None,
       "summary exists" if _file_text(SUMMARY_PATH) else "summary missing")

    # 20. Test file exists
    ok("test_file_exists", _file_text(TEST_PATH) is not None,
       str(TEST_PATH.relative_to(ROOT)) if _file_text(TEST_PATH) else "test file missing")

    return results


def self_test():
    """Smoke-test that all checks produce valid output."""
    results = _checks()
    assert len(results) >= 20, f"Expected >=20 checks, got {len(results)}"
    for r in results:
        assert "check" in r and "passed" in r and "detail" in r
    print(f"self_test: {len(results)} checks OK", file=sys.stderr)
    return True


def main():
    if "--self-test" in sys.argv:
        self_test()
        return

    results = _checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    verdict = "PASS" if passed == total else "FAIL"

    if "--json" in sys.argv:
        print(json.dumps({
            "bead_id": BEAD,
            "section": SECTION,
            "title": TITLE,
            "gate_script": "check_region_owned_lifecycle.py",
            "checks_passed": passed,
            "checks_total": total,
            "verdict": verdict,
            "checks": results,
        }, indent=2))
    else:
        print(f"=== {TITLE} ({BEAD}) ===")
        print(f"Section: {SECTION}\n")
        for r in results:
            mark = "PASS" if r["passed"] else "FAIL"
            print(f"  [{mark}] {r['check']}: {r['detail']}")
        print(f"\n{BEAD}: {passed}/{total} checks -- {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
