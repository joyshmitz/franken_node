# bd-1pk Doctor Diagnostics Contract Checks

- Log: `artifacts/section_bootstrap/bd-1pk/doctor_diagnostics_log.jsonl`
- Checks JSON: `artifacts/section_bootstrap/bd-1pk/doctor_contract_checks.json`
- Matrix JSON: `artifacts/section_bootstrap/bd-1pk/doctor_checks_matrix.json`
- Sample reports: `doctor_report_healthy.json`, `doctor_report_degraded.json`, `doctor_report_failure.json`, `doctor_report_invalid_input.json`

| Check | Pass | Detail |
|---|---|---|
| exists_main.rs | true | /data/projects/franken_node/crates/franken-node/src/main.rs |
| exists_cli.rs | true | /data/projects/franken_node/crates/franken-node/src/cli.rs |
| exists_bootstrap_doctor_contract.md | true | /data/projects/franken_node/docs/specs/bootstrap_doctor_contract.md |
| doctor_args_json_flag | true | --json |
| doctor_args_trace_id_flag | true | --trace-id |
| doctor_args_policy_activation_input_flag | true | --policy-activation-input |
| doctor_args_trace_id_default | true | doctor-bootstrap |
| doctor_report_has_structured_logs | true | DoctorReport structured logs |
| doctor_report_has_merge_decisions | true | merge provenance |
| doctor_builder_with_cwd | true | cwd injectable builder |
| doctor_builder_with_policy_input | true | policy input injectable builder |
| doctor_policy_activation_runner | true | policy activation pipeline runner |
| doctor_json_output_path | true | json render |
| doctor_human_output_path | true | human render |
| doctor_code_DR-CONFIG-001 | true | DR-CONFIG-001 |
| doctor_code_DR-CONFIG-002 | true | DR-CONFIG-002 |
| doctor_code_DR-PROFILE-003 | true | DR-PROFILE-003 |
| doctor_code_DR-TRUST-004 | true | DR-TRUST-004 |
| doctor_code_DR-MIGRATE-005 | true | DR-MIGRATE-005 |
| doctor_code_DR-OBS-006 | true | DR-OBS-006 |
| doctor_code_DR-ENV-007 | true | DR-ENV-007 |
| doctor_code_DR-CONFIG-008 | true | DR-CONFIG-008 |
| doctor_code_DR-POLICY-009 | true | DR-POLICY-009 |
| doctor_code_DR-POLICY-010 | true | DR-POLICY-010 |
| doctor_code_DR-POLICY-011 | true | DR-POLICY-011 |
| doctor_event_code_DOC-001 | true | DOC-001 |
| doctor_event_code_DOC-002 | true | DOC-002 |
| doctor_event_code_DOC-003 | true | DOC-003 |
| doctor_event_code_DOC-004 | true | DOC-004 |
| doctor_event_code_DOC-005 | true | DOC-005 |
| doctor_event_code_DOC-006 | true | DOC-006 |
| doctor_event_code_DOC-007 | true | DOC-007 |
| doctor_event_code_DOC-008 | true | DOC-008 |
| doctor_event_code_DOC-009 | true | DOC-009 |
| doctor_event_code_DOC-010 | true | DOC-010 |
| doctor_event_code_DOC-011 | true | DOC-011 |
| doctor_code_order_deterministic | true | [26027, 26386, 27272, 28162, 29052, 29991, 30868, 31731, 33383, 35554, 38122] |
| contract_has_matrix_and_schema | true | matrix+schema sections |
| contract_mentions_policy_activation_flag | true | policy activation command surface |
| contract_mentions_policy_codes | true | policy code rows |
| report_exists_doctor_report_healthy.json | true | artifacts/section_bootstrap/bd-1pk/doctor_report_healthy.json |
| report_valid_json_doctor_report_healthy.json | true | valid json |
| report_exists_doctor_report_degraded.json | true | artifacts/section_bootstrap/bd-1pk/doctor_report_degraded.json |
| report_valid_json_doctor_report_degraded.json | true | valid json |
| report_exists_doctor_report_failure.json | true | artifacts/section_bootstrap/bd-1pk/doctor_report_failure.json |
| report_valid_json_doctor_report_failure.json | true | valid json |
| report_exists_doctor_report_invalid_input.json | true | artifacts/section_bootstrap/bd-1pk/doctor_report_invalid_input.json |
| report_valid_json_doctor_report_invalid_input.json | true | valid json |
| policy_pass_statuses | true | {'DR-POLICY-009': 'pass', 'DR-POLICY-010': 'pass', 'DR-POLICY-011': 'pass'} |
| policy_warn_statuses | true | {'DR-POLICY-009': 'warn', 'DR-POLICY-010': 'pass', 'DR-POLICY-011': 'pass'} |
| policy_block_statuses | true | {'DR-POLICY-009': 'fail', 'DR-POLICY-010': 'fail', 'DR-POLICY-011': 'pass'} |
| policy_invalid_statuses | true | {'DR-POLICY-009': 'fail', 'DR-POLICY-010': 'fail', 'DR-POLICY-011': 'fail'} |
| policy_pass_dominant_verdict_allow | true | allow |
| policy_warn_dominant_verdict_warn | true | warn |
| policy_block_dominant_verdict_block | true | block |
| policy_block_contains_conformal_budget | true | ['conformal_risk'] |
| policy_invalid_omits_policy_activation | true | None |
| policy_pass_decision_reason | true | TopCandidateAccepted |
| policy_warn_decision_reason | true | TopCandidateAccepted |
| policy_block_decision_reason | true | AllCandidatesBlocked |
| policy_pass_top_ranked_candidate | true | balanced_patch |
| policy_warn_conformal_finding_warn | true | {'monitor_name': 'ConformalRiskGuardrail', 'budget_id': 'conformal_risk', 'verdict': 'warn', 'event_code': 'EVD-GUARD-003', 'anytime_valid': True, 'reason': 'conformal-risk upper error bound 0.074 exceeds warn threshold 0.070 (empirical 0.055, n=5000, delta=0.0100)'} |
| policy_invalid_message_mentions_parse_failure | true | Policy activation input failed to load: failed parsing policy activation input /data/projects/franken_node/fixtures/policy_activation/doctor_policy_activation_invalid.json as JSON |
| matrix_written | true | /data/projects/franken_node/artifacts/section_bootstrap/bd-1pk/doctor_checks_matrix.json |
| healthy_report_deterministic_hash | true | 15dc287bb8821ade48ae963ae61ad03be954c2b79463db88382fc192fb468dca |

Verdict: **PASS** (65/65)
