"""Unit tests for scripts/check_checkpoint_placement.py."""

from __future__ import annotations

import json
import unittest

from scripts.check_checkpoint_placement import _check_evidence_fields, _contains_all, self_test


class CheckCheckpointPlacementTests(unittest.TestCase):
    def test_contains_all_passes_when_tokens_present(self) -> None:
        ok, missing = _contains_all("alpha beta gamma", ["alpha", "gamma"])
        self.assertTrue(ok)
        self.assertEqual(missing, [])

    def test_contains_all_reports_missing(self) -> None:
        ok, missing = _contains_all("alpha beta", ["alpha", "delta"])
        self.assertFalse(ok)
        self.assertEqual(missing, ["delta"])

    def test_check_evidence_fields_validates_metrics(self) -> None:
        ok, missing = _check_evidence_fields(
            {
                "verification_metrics": {
                    "checkpoints_written": 1,
                    "checkpoints_resumed_from": 1,
                    "checkpoint_contract_violations": 0,
                    "hash_chain_verifications_passed": 1,
                    "avg_iterations_between_checkpoints": 100,
                }
            }
        )
        self.assertTrue(ok)
        self.assertEqual(missing, [])

    def test_self_test_returns_passing_payload(self) -> None:
        ok, payload = self_test()
        self.assertTrue(ok)
        self.assertEqual(payload["self_test"], "passed")
        json.dumps(payload)


if __name__ == "__main__":
    unittest.main()
