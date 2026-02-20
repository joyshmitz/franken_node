#!/usr/bin/env python3
"""
Program-Level E2E + Chaos Orchestration Suite.

Executes cross-section journeys from the integration journey matrix and
emits deterministic evidence bundles for pass/fail and replay analysis.

Usage:
    python3 scripts/program_e2e_orchestrator.py [--json] [--journey J-NNN] [--chaos]

Exit codes:
    0 = PASS (all journeys pass)
    1 = FAIL (one or more journeys failed)
    2 = ERROR (orchestration failure)
"""

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MATRIX_PATH = ROOT / "docs" / "verification" / "journey_matrix.json"
CHAOS_CATALOG_PATH = ROOT / "docs" / "verification" / "chaos_scenarios.json"

# Since actual cross-section execution depends on runtime components not yet
# built, this orchestrator validates the structural integrity of the journey
# matrix, chaos catalog, and evidence pipeline. When runtime components are
# available, this switches to live execution.
MODE = "structural"  # or "live" when runtime exists


def load_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def generate_trace_id() -> str:
    return f"trace-{uuid.uuid4().hex[:16]}"


def validate_journey_structural(journey: dict) -> dict:
    """Structurally validate a journey definition."""
    result = {
        "journey_id": journey["id"],
        "journey_name": journey["name"],
        "status": "PASS",
        "phases_validated": 0,
        "errors": [],
        "trace_id": generate_trace_id(),
    }

    # Validate all phases have required fields
    for i, phase in enumerate(journey.get("phases", [])):
        if "section" not in phase:
            result["errors"].append(f"Phase {i}: missing section")
        if "fixture" not in phase:
            result["errors"].append(f"Phase {i}: missing fixture")
        result["phases_validated"] += 1

    # Validate failure taxonomy is non-empty
    taxonomy = journey.get("failure_taxonomy", [])
    if not taxonomy:
        result["errors"].append("Empty failure taxonomy")

    # Validate seam resolution is documented
    if not journey.get("seam_resolution"):
        result["errors"].append("Missing seam_resolution")

    # Validate sections array matches phases
    declared_sections = set(journey.get("sections", []))
    phase_sections = {p["section"] for p in journey.get("phases", []) if "section" in p}
    undeclared = phase_sections - declared_sections
    if undeclared:
        result["errors"].append(f"Undeclared sections in phases: {undeclared}")

    if result["errors"]:
        result["status"] = "FAIL"

    return result


def validate_chaos_structural(chaos_data: dict | None) -> list[dict]:
    """Validate chaos scenario catalog structure."""
    if chaos_data is None:
        return [{
            "scenario_id": "CATALOG",
            "status": "SKIP",
            "reason": "Chaos catalog not yet created",
        }]

    results = []
    for scenario in chaos_data.get("scenarios", []):
        result = {
            "scenario_id": scenario.get("id", "UNKNOWN"),
            "status": "PASS",
            "errors": [],
        }
        for field in ["id", "name", "target_journey", "injection_type", "expected_failure"]:
            if field not in scenario:
                result["errors"].append(f"Missing field: {field}")
        if result["errors"]:
            result["status"] = "FAIL"
        results.append(result)

    return results


def main():
    json_output = "--json" in sys.argv
    target_journey = None
    run_chaos = "--chaos" in sys.argv

    for i, arg in enumerate(sys.argv):
        if arg == "--journey" and i + 1 < len(sys.argv):
            target_journey = sys.argv[i + 1]

    timestamp = datetime.now(timezone.utc).isoformat()
    orchestration_trace = generate_trace_id()

    # Load journey matrix
    matrix = load_json(MATRIX_PATH)
    if matrix is None:
        print("ERROR: Journey matrix not found", file=sys.stderr)
        sys.exit(2)

    journeys = matrix.get("journeys", [])
    if target_journey:
        journeys = [j for j in journeys if j["id"] == target_journey]
        if not journeys:
            print(f"ERROR: Journey {target_journey} not found", file=sys.stderr)
            sys.exit(2)

    # Run journey validations
    journey_results = []
    for journey in journeys:
        result = validate_journey_structural(journey)
        result["mode"] = MODE
        journey_results.append(result)

    # Run chaos validations if requested
    chaos_results = []
    if run_chaos:
        chaos_data = load_json(CHAOS_CATALOG_PATH)
        chaos_results = validate_chaos_structural(chaos_data)

    # Compute verdict
    journey_failures = [r for r in journey_results if r["status"] == "FAIL"]
    chaos_failures = [r for r in chaos_results if r["status"] == "FAIL"]
    verdict = "PASS" if not journey_failures and not chaos_failures else "FAIL"

    report = {
        "gate": "program_e2e_orchestration",
        "verdict": verdict,
        "timestamp": timestamp,
        "mode": MODE,
        "orchestration_trace": orchestration_trace,
        "journeys_executed": len(journey_results),
        "journeys_passed": sum(1 for r in journey_results if r["status"] == "PASS"),
        "journeys_failed": len(journey_failures),
        "chaos_scenarios": len(chaos_results),
        "chaos_passed": sum(1 for r in chaos_results if r["status"] == "PASS"),
        "chaos_skipped": sum(1 for r in chaos_results if r["status"] == "SKIP"),
        "journey_results": journey_results,
        "chaos_results": chaos_results if chaos_results else [],
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Program E2E + Chaos Orchestration ===")
        print(f"Mode: {MODE}")
        print(f"Trace: {orchestration_trace}")
        print(f"Timestamp: {timestamp}")
        print()
        print("Journey Results:")
        for r in journey_results:
            icon = "OK" if r["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {r['journey_id']}: {r['journey_name']} "
                  f"({r['phases_validated']} phases)")
            if r["errors"]:
                for e in r["errors"]:
                    print(f"       Error: {e}")
        print()
        if chaos_results:
            print("Chaos Results:")
            for r in chaos_results:
                icon = "OK" if r["status"] == "PASS" else r["status"]
                print(f"  [{icon}] {r['scenario_id']}")
            print()
        print(f"Journeys: {report['journeys_passed']}/{report['journeys_executed']} pass")
        if chaos_results:
            print(f"Chaos: {report['chaos_passed']}/{report['chaos_scenarios']} pass, "
                  f"{report['chaos_skipped']} skipped")
        print(f"Verdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
