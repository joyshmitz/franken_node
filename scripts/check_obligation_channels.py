#!/usr/bin/env python3
"""Compatibility wrapper for bd-2ah checker naming.

Canonical implementation lives in `check_obligation_channel_protocol.py`.
This wrapper preserves the expected bead artifact path:
`scripts/check_obligation_channels.py`.
"""

from __future__ import annotations

import json
import sys

import check_obligation_channel_protocol as protocol
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging


def run_all() -> dict:
    """Run full verification via canonical protocol checker."""
    return protocol.run_all()


def self_test() -> dict:
    """Run checker self-test via canonical protocol checker."""
    return protocol.self_test()


def main() -> None:
    logger = configure_test_logging("check_obligation_channels")
    as_json = "--json" in sys.argv
    if "--self-test" in sys.argv:
        payload = self_test()
        if as_json:
            print(json.dumps(payload, indent=2))
        else:
            print("self_test passed" if payload["verdict"] == "PASS" else "self_test failed")
        raise SystemExit(0 if payload["verdict"] == "PASS" else 1)

    payload = run_all()
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        print(
            f"{payload['bead_id']} {payload['title']} — "
            f"{payload['passed']}/{payload['total']} checks ({payload['verdict']})"
        )

    raise SystemExit(0 if payload.get("all_passed") else 1)


if __name__ == "__main__":
    main()
