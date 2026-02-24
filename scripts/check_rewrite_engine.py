#!/usr/bin/env python3
"""
Rewrite Suggestion Engine Verifier.

Usage:
    python3 scripts/check_rewrite_engine.py [--json]
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
sys.path.insert(0, str(ROOT / "scripts"))
import rewrite_suggestion_engine as engine


def main():
    logger = configure_test_logging("check_rewrite_engine")
    json_output = "--json" in sys.argv
    result = engine.self_test()

    if json_output:
        print(json.dumps(result, indent=2))
    else:
        print("=== Rewrite Engine Verifier ===")
        for c in result["checks"]:
            print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
        print(f"\nVerdict: {result['verdict']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
