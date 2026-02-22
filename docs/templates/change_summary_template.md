# Change Summary Contract Template

Every proposal/PR that changes subsystem runtime or control-plane code must include a machine-parseable change summary companion file under `docs/change_summaries/`.

Use `docs/change_summaries/<date>-<slug>.json` and follow this contract.

## Required Fields

1. `intent`: one-line change intent statement.
2. `scope`: affected subsystems and concrete modules/files.
3. `surface_area_delta`: new APIs, removed APIs, changed signatures.
4. `affected_contracts`: related bead IDs and linked contract/spec documents.
5. `operational_impact`: what operators need to know and do.
6. `risk_delta`: pre/post risk tier and rationale.
7. `compatibility`: backward + forward compatibility assessment.
8. `dependency_changes`: added/removed/updated dependencies.
9. `compatibility_and_threat_evidence`: compatibility test evidence + threat vector mitigations.
10. `ev_score_and_tier`: EV score, tier, and per-dimension verification evidence.
11. `expected_loss_model`: scenario-based expected-loss model with aggregate and confidence interval.
12. `fallback_trigger`: deterministic fallback trigger contract with latency/RTO bounds.
13. `rollout_wedge`: staged rollout contract with blast-radius and observation controls.
14. `rollback_command`: tested rollback command, scope boundaries, and expected execution time.
15. `benchmark_and_correctness_artifacts`: benchmark metric comparisons and correctness evidence references.

## JSON Template

```json
{
  "summary_id": "chg-YYYYMMDD-<slug>",
  "contract_version": "1.0",
  "change_summary": {
    "intent": "One-line intent statement.",
    "scope": {
      "subsystems": ["franken_node.connector"],
      "modules": ["crates/franken-node/src/connector/example.rs"]
    },
    "surface_area_delta": {
      "new_apis": [],
      "removed_apis": [],
      "changed_signatures": []
    },
    "affected_contracts": {
      "beads": ["bd-xxxx"],
      "documents": ["docs/specs/example_contract.md"]
    },
    "operational_impact": {
      "operator_notes": "Operational implications for rollout/monitoring.",
      "required_actions": ["Run migration check before deploy."],
      "rollout_notes": "Canary first, then full rollout."
    },
    "risk_delta": {
      "previous_tier": "medium",
      "new_tier": "low",
      "rationale": "Deterministic validation removed a manual failure mode."
    },
    "compatibility": {
      "backward_compatibility": "compatible",
      "forward_compatibility": "enables",
      "details": "Adds contract checks without changing runtime behavior."
    },
    "dependency_changes": {
      "added": [],
      "removed": [],
      "updated": []
    },
    "compatibility_and_threat_evidence": {
      "compatibility_test_suites": [
        {
          "suite_name": "tests/conformance/example_suite.rs",
          "pass_count": 12,
          "fail_count": 0,
          "artifact_path": "artifacts/11/example_compatibility_report.json"
        }
      ],
      "regression_risk_assessment": {
        "risk_level": "medium",
        "api_families": ["POST /v1/example", "CLI: franken-node example"],
        "notes": "Added validation in existing control path; no removed interfaces."
      },
      "threat_vectors": [
        {
          "vector": "privilege_escalation",
          "mitigation": "Capability checks are enforced at boundary admission."
        },
        {
          "vector": "data_exfiltration",
          "mitigation": "Sensitive payloads are redacted in transport logs."
        },
        {
          "vector": "denial_of_service",
          "mitigation": "Rate limits and bounded retries prevent unbounded amplification."
        }
      ]
    },
    "ev_score_and_tier": {
      "ev_score": 72,
      "tier": "T3",
      "dimension_scores": {
        "code_review": {
          "score": 0.8,
          "evidence_ref": "artifacts/11/benchmark_correctness_contract.json",
          "assessed_at": "2026-02-21T00:00:00Z"
        },
        "test_coverage": {
          "score": 0.7,
          "evidence_ref": "artifacts/section_11/bd-3l8d/correctness_suite_output.txt",
          "assessed_at": "2026-02-21T00:00:00Z"
        },
        "security_audit": {
          "score": 0.75,
          "evidence_ref": "artifacts/11/compatibility_threat_evidence_contract.json",
          "assessed_at": "2026-02-21T00:00:00Z"
        },
        "supply_chain": {
          "score": 0.65,
          "evidence_ref": "artifacts/11/rollback_command_contract.json",
          "assessed_at": "2026-02-21T00:00:00Z"
        },
        "conformance": {
          "score": 0.7,
          "evidence_ref": "artifacts/section_11/bd-3l8d/benchmark_metrics.json",
          "assessed_at": "2026-02-21T00:00:00Z"
        }
      },
      "rationale": "Tier T3 justified by consistent conformance and audit-backed controls."
    },
    "expected_loss_model": {
      "scenarios": [
        {
          "name": "rollback-command regression",
          "probability": 0.1,
          "impact_value": 250,
          "impact_unit": "dollars",
          "mitigation": "Rollback command exercised in CI and canary."
        },
        {
          "name": "compatibility divergence",
          "probability": 0.05,
          "impact_value": 1200,
          "impact_unit": "dollars",
          "mitigation": "Lockstep verification suite blocks promotion."
        },
        {
          "name": "operator runbook delay",
          "probability": 0.2,
          "impact_value": 80,
          "impact_unit": "dollars",
          "mitigation": "Structured playbook with on-call escalation."
        }
      ],
      "aggregate_expected_loss": 101,
      "confidence_interval": {
        "lower": 80,
        "upper": 140,
        "confidence_level": 0.95
      },
      "loss_category": "minor"
    },
    "fallback_trigger": {
      "trigger_conditions": [
        "error_rate > 0.05 over 60s sliding window"
      ],
      "fallback_target_state": "last_known_good_checkpoint",
      "rollback_mechanism": "automatic",
      "max_detection_latency_s": 3,
      "recovery_time_objective_s": 20,
      "subsystem_id": "franken_node.control_plane",
      "rationale": "Fast fallback keeps failure blast radius bounded during staged rollout."
    },
    "rollout_wedge": {
      "wedge_stages": [
        {
          "stage_id": "canary-5",
          "target_percentage": 5,
          "duration_hours": 2,
          "success_criteria": ["error_rate <= 0.02", "p95_latency_ms <= 35"],
          "rollback_trigger": "error_rate > 0.05"
        },
        {
          "stage_id": "regional-20",
          "target_percentage": 20,
          "duration_hours": 4,
          "success_criteria": ["error_rate <= 0.02", "no critical alerts"],
          "rollback_trigger": "critical_alert_count > 0"
        }
      ],
      "initial_percentage": 5,
      "increment_policy": "manual",
      "max_blast_radius": 25,
      "observation_window_hours": 1,
      "wedge_state": "ACTIVE"
    },
    "rollback_command": {
      "command": "franken-node rollback apply --receipt artifacts/rollback/example_receipt.json --force-safe",
      "idempotent": true,
      "tested_in_ci": true,
      "test_evidence_artifact": "artifacts/section_11/bd-nglx/rollback_command_ci_test.json",
      "rollback_scope": {
        "reverts": [
          "runtime policy configuration",
          "service feature-flag activation"
        ],
        "does_not_revert": [
          "already-emitted audit logs",
          "externally processed events"
        ]
      },
      "estimated_duration": "2m"
    },
    "benchmark_and_correctness_artifacts": {
      "benchmark_metrics": [
        {
          "metric_name": "p95_latency_ms",
          "unit": "ms",
          "measured_value": 31.4,
          "baseline_value": 29.8,
          "delta": 1.6,
          "within_acceptable_bounds": true,
          "artifact_path": "artifacts/section_11/bd-3l8d/benchmark_metrics.json"
        }
      ],
      "correctness_suites": [
        {
          "suite_name": "tests/security/control_epoch_validity.rs",
          "pass_count": 6,
          "fail_count": 0,
          "coverage_percent": 92.1,
          "raw_output_artifact": "artifacts/section_11/bd-3l8d/correctness_suite_output.txt"
        }
      ]
    }
  }
}
```

## Enforcement

- CI gate: `.github/workflows/change-summary-contract-gate.yml`
- Validator: `scripts/check_change_summary_contract.py`
- Unit tests: `tests/test_check_change_summary_contract.py`
