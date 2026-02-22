# bd-1pk Doctor Diagnostics Contract Checks

- Log: `artifacts/section_bootstrap/bd-1pk/doctor_diagnostics_log.jsonl`
- Checks JSON: `artifacts/section_bootstrap/bd-1pk/doctor_contract_checks.json`
- Matrix JSON: `artifacts/section_bootstrap/bd-1pk/doctor_checks_matrix.json`
- Sample reports: `doctor_report_healthy.json`, `doctor_report_degraded.json`, `doctor_report_failure.json`

| Check | Pass | Detail |
|---|---|---|
| exists_main.rs | true | /data/projects/franken_node/crates/franken-node/src/main.rs |
| exists_cli.rs | true | /data/projects/franken_node/crates/franken-node/src/cli.rs |
| exists_bootstrap_doctor_contract.md | true | /data/projects/franken_node/docs/specs/bootstrap_doctor_contract.md |
| doctor_args_json_flag | true | --json |
| doctor_args_trace_id_flag | true | --trace-id |
| doctor_args_trace_id_default | true | doctor-bootstrap |
| doctor_report_has_structured_logs | true | DoctorReport structured logs |
| doctor_report_has_merge_decisions | true | merge provenance |
| doctor_builder_with_cwd | true | cwd injectable builder |
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
| doctor_event_code_DOC-001 | true | DOC-001 |
| doctor_event_code_DOC-002 | true | DOC-002 |
| doctor_event_code_DOC-003 | true | DOC-003 |
| doctor_event_code_DOC-004 | true | DOC-004 |
| doctor_event_code_DOC-005 | true | DOC-005 |
| doctor_event_code_DOC-006 | true | DOC-006 |
| doctor_event_code_DOC-007 | true | DOC-007 |
| doctor_event_code_DOC-008 | true | DOC-008 |
| doctor_code_order_deterministic | true | [14334, 14693, 15579, 16444, 17334, 18248, 19125, 19988] |
| contract_has_matrix_and_schema | true | matrix+schema sections |
| matrix_written | true | /data/projects/franken_node/artifacts/section_bootstrap/bd-1pk/doctor_checks_matrix.json |
| healthy_report_written | true | /data/projects/franken_node/artifacts/section_bootstrap/bd-1pk/doctor_report_healthy.json |
| degraded_report_written | true | /data/projects/franken_node/artifacts/section_bootstrap/bd-1pk/doctor_report_degraded.json |
| failure_report_written | true | /data/projects/franken_node/artifacts/section_bootstrap/bd-1pk/doctor_report_failure.json |
| healthy_report_deterministic_hash | true | b4e79d33da13773659cecf849739c4bbfd2f1a229117aae4dccd8e91bb3d8eb1 |

Verdict: **PASS** (34/34)
