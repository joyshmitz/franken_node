# bd-32e Init Bootstrap Contract Checks

- Log: `artifacts/section_bootstrap/bd-32e/init_bootstrap_log.jsonl`
- Checks JSON: `artifacts/section_bootstrap/bd-32e/init_contract_checks.json`
- Snapshots JSON: `artifacts/section_bootstrap/bd-32e/init_snapshots.json`

| Check | Pass | Detail |
|---|---|---|
| exists_main.rs | true | /data/projects/franken_node/crates/franken-node/src/main.rs |
| exists_cli.rs | true | /data/projects/franken_node/crates/franken-node/src/cli.rs |
| exists_bootstrap_init_contract.md | true | /data/projects/franken_node/docs/specs/bootstrap_init_contract.md |
| exists_franken_node.profile_examples.toml | true | /data/projects/franken_node/config/franken_node.profile_examples.toml |
| cli_init_overwrite_flag | true | pub overwrite: bool |
| cli_init_backup_flag | true | pub backup_existing: bool |
| cli_init_json_flag | true | pub json: bool |
| cli_init_trace_id_flag | true | pub trace_id: String |
| init_trace_id_default | true | init-bootstrap |
| init_profile_template_embedded | true | PROFILE_EXAMPLES_TEMPLATE |
| init_flag_validation | true | validate_init_flags( |
| init_write_policy_function | true | apply_init_write_policy( |
| init_mutual_exclusion_error | true | --overwrite and --backup-existing are mutually exclusive |
| init_writes_profile_example_file | true | franken_node.profile_examples.toml |
| init_non_destructive_default | true | refusing to overwrite existing file |
| init_contract_sections_present | true | policy+schema |
| snapshots_written | true | /data/projects/franken_node/artifacts/section_bootstrap/bd-32e/init_snapshots.json |
| snapshots_hash_stable | true | f9d4c6d3cf494aee3fd677e3f19c5507b9657b80d39c081ed7cbc26783550ece |

Verdict: **PASS** (18/18)
