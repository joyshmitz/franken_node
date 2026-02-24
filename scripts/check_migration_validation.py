#!/usr/bin/env python3
"""
Migration Validation Runner Verifier.

Usage:
    python3 scripts/check_migration_validation.py [--json]
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import migration_validation_runner as runner
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging


def main():
    logger = configure_test_logging("check_migration_validation")
    json_output = "--json" in sys.argv
    result = runner.self_test()

    if json_output:
        print(json.dumps(result, indent=2))
    else:
        print("=== Migration Validation Verifier ===")
        for c in result["checks"]:
            print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
        print(f"\nVerdict: {result['verdict']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
