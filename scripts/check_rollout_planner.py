#!/usr/bin/env python3
"""Rollout Planner Verifier. Usage: python3 scripts/check_rollout_planner.py [--json]"""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import rollout_planner as planner

def main():
    json_output = "--json" in sys.argv
    result = planner.self_test()
    if json_output:
        print(json.dumps(result, indent=2))
    else:
        for c in result["checks"]:
            print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
        print(f"\nVerdict: {result['verdict']}")
    sys.exit(0 if result["verdict"] == "PASS" else 1)

if __name__ == "__main__":
    main()
