# bd-n9r Config Resolution Contract Checks

- Log: `artifacts/section_bootstrap/bd-n9r/config_resolution_log.jsonl`
- Checks JSON: `artifacts/section_bootstrap/bd-n9r/contract_checks.json`
- Snapshot JSON: `artifacts/section_bootstrap/bd-n9r/resolved_config_snapshot.json`

| Check | Pass | Detail |
|---|---|---|
| exists_config.rs | true | /data/projects/franken_node/crates/franken-node/src/config.rs |
| exists_cli.rs | true | /data/projects/franken_node/crates/franken-node/src/cli.rs |
| exists_main.rs | true | /data/projects/franken_node/crates/franken-node/src/main.rs |
| exists_franken_node.profile_examples.toml | true | /data/projects/franken_node/config/franken_node.profile_examples.toml |
| exists_bootstrap_config_contract.md | true | /data/projects/franken_node/docs/specs/bootstrap_config_contract.md |
| resolver_entrypoint | true | Config::resolve |
| env_override_layer | true | env layer |
| merge_decision_struct | true | MergeDecision |
| merge_stage_enum | true | MergeStage |
| precedence_doc_string | true | resolver precedence |
| contract_precedence_doc | true | contract precedence |
| main_init_uses_resolver | true | count=2 |
| main_doctor_outputs_decisions | true | doctor merge tracing |
| cli_init_config_option | true | InitArgs --config |
| cli_doctor_config_option | true | count=3 |
| cli_profile_options | true | count=2 |
| example_profile_present | true | balanced |
| example_profiles_table | true | profiles table |
| example_profiles_strict | true | profiles.strict |
| example_profiles_balanced | true | profiles.balanced |
| example_profiles_legacy | true | profiles.legacy-risky |
| snapshot_written | true | /data/projects/franken_node/artifacts/section_bootstrap/bd-n9r/resolved_config_snapshot.json |
| snapshot_sha256 | true | 182eebca3e72c9220e4522f4114e1ff3f869f84af1f66a32b0de0d76c98f159a |

Verdict: **PASS** (23/23)
