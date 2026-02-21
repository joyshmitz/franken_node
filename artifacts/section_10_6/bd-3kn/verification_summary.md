# bd-3kn: Packaging Profiles -- Verification Summary

## Bead
- **ID**: bd-3kn
- **Section**: 10.6
- **Title**: Add packaging profiles for local/dev/enterprise deployments

## Artifacts Created
1. `docs/specs/section_10_6/bd-3kn_contract.md` -- Spec contract with invariants, event codes, component matrix
2. `docs/policy/packaging_profiles.md` -- Policy document with profile definitions, size budgets, feature flags
3. `packaging/profiles.toml` -- Profile configuration file (3 profiles, 4 sections each)
4. `scripts/check_packaging_profiles.py` -- Verification script (18 checks)
5. `tests/test_check_packaging_profiles.py` -- Unit tests (47 tests)
6. `artifacts/section_10_6/bd-3kn/verification_evidence.json` -- Gate results

## Profiles Defined

| Profile | Components | Telemetry | Audit | Startup | Max Size |
|---------|-----------|-----------|-------|---------|----------|
| `local` | Core binary only | Off | Disabled | Lazy | 25 MB |
| `dev` | Core + debug symbols + lockstep + fixtures | Debug-local | Disabled | Eager | 60 MB |
| `enterprise` | Core + compliance + audit + signing + telemetry | Structured-export | Mandatory | Full-integrity | 80 MB |

## Verification Results
- **file_exists: spec contract**: PASS -- spec contract present
- **file_exists: policy document**: PASS -- policy document present
- **file_exists: profiles.toml**: PASS -- profiles.toml present
- **profiles_toml_three_profiles**: PASS -- all 3 profiles defined
- **profiles_toml_components**: PASS -- all component sections present
- **profiles_toml_defaults**: PASS -- all default sections present
- **profiles_toml_startup**: PASS -- all startup sections present
- **profiles_toml_size_budget**: PASS -- all size_budget sections present
- **spec_event_codes**: PASS -- all 4 event codes (PKG-001 through PKG-004) present
- **spec_invariants**: PASS -- all 8 invariants (INV-PKG-*) present
- **policy_event_codes**: PASS -- all 4 event codes in policy
- **policy_invariants**: PASS -- all 8 invariants in policy
- **local_telemetry_off**: PASS -- telemetry = "off" in local profile
- **enterprise_audit_mandatory**: PASS -- audit_logging = true in enterprise
- **enterprise_integrity_check**: PASS -- integrity_self_check = true in enterprise
- **spec_size_constraint**: PASS -- 30% size constraint documented
- **spec_cli_flag**: PASS -- --profile CLI flag documented
- **spec_env_var**: PASS -- FRANKEN_NODE_PROFILE env var documented

## Test Results
- 47 unit tests: all passed
- 18 verification checks: all passed

## Verdict: PASS
