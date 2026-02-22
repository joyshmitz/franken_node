# bd-3k9t Foundation E2E Summary

- Verdict: **PASS**
- Stage pass/fail: **6/6**
- Coverage: clean=4, degraded=1, drifted=1

| Stage | Category | Status | Expected Exit | Actual Exit |
|---|---|---|---:|---:|
| run_surface_contract | clean | pass | 0 | 0 |
| config_profile_resolution | clean | pass | 0 | 0 |
| init_profile_bootstrap | clean | pass | 0 | 0 |
| doctor_command_diagnostics | clean | pass | 0 | 0 |
| transplant_verify_missing_snapshot | degraded | pass | 2 | 2 |
| transplant_drift_probe_missing_snapshot | drifted | pass | 2 | 2 |

- Log: `artifacts/section_bootstrap/bd-3k9t/foundation_e2e_log.jsonl`
- Summary JSON: `artifacts/section_bootstrap/bd-3k9t/foundation_e2e_summary.json`
- Bundle JSON: `artifacts/section_bootstrap/bd-3k9t/foundation_e2e_bundle.json`
