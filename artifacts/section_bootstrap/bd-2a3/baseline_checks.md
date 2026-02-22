# bd-2a3 Baseline Checks (rch offload)

- Trace ID: `trace-bd-2a3-rch`
- Verdict: **FAIL**
- rch doctor exit code: `0`
- Command log: `artifacts/section_bootstrap/bd-2a3/rch_command_log.jsonl`

| Check | Code | Command | Status | Exit | Duration (ms) | Log |
|---|---|---|---|---|---:|---|
| cargo_fmt_check | `BD2A3-FMT-FAIL` | `cargo fmt --check` | fail | 1 | 1864 | `artifacts/section_bootstrap/bd-2a3/cargo_fmt_check.log` |
| cargo_check_all_targets | `BD2A3-CHECK-FAIL` | `cargo check --all-targets` | fail | 101 | 141720 | `artifacts/section_bootstrap/bd-2a3/cargo_check_all_targets.log` |
| cargo_clippy_all_targets | `BD2A3-CLIPPY-FAIL` | `cargo clippy --all-targets -- -D warnings` | fail | 101 | 91709 | `artifacts/section_bootstrap/bd-2a3/cargo_clippy_all_targets.log` |

## Failure Excerpts
- **cargo_fmt_check**: 106:     /// Authentication failed (401).
219:     /// Scope validation failed.
237:(B[m     /// Rollback failed during release.
308:(B[m[31m-                FleetControlError::rollback_failed(incident_id, "incident not found")
310:(B[m[32m+            .ok_or_else(|| FleetControlError::rollback_failed(incident_id, "incident not found"))?;
313:             return Err(FleetControlError::rollback_failed(
1343:                 write!(f, "preimage construction failed: {reason}")
2213:     /// Quorum failed: insufficient acks.
- **cargo_check_all_targets**: 98:[1m[91merror[E0599][0m[1m: no function or associated item named `new` found for struct `CoreWrapper<T>` in the current scope[0m
117:[1m[91merror[E0599][0m[1m: no function or associated item named `new` found for struct `CoreWrapper<T>` in the current scope[0m
138:[1m[33mwarning[0m: build failed, waiting for other jobs to finish...
143:[1m[94m12[0m [1m[94m|[0m use super::error::{ApiError, ProblemDetail};
264:[1m[91merror[E0423][0m[1m: expected function, tuple struct or tuple variant, found enum `Capability`[0m
277:[1m[91merror[E0423][0m[1m: expected function, tuple struct or tuple variant, found enum `Capability`[0m
290:[1m[91merror[E0423][0m[1m: expected function, tuple struct or tuple variant, found enum `Capability`[0m
311:[1m[91merror[E0599][0m[1m: no function or associated item named `new` found for struct `CoreWrapper<T>` in the current scope[0m
- **cargo_clippy_all_targets**: 38:[1m[91merror[E0599][0m[1m: no function or associated item named `new` found for struct `hmac::digest::core_api::CoreWrapper<T>` in the current scope[0m
59:[1m[33mwarning[0m: build failed, waiting for other jobs to finish...
140:[1m[91merror[E0599][0m[1m: no function or associated item named `new` found for struct `sha2::digest::core_api::CoreWrapper<T>` in the current scope[0m
163:[1m[94m12[0m [1m[94m|[0m use super::error::{ApiError, ProblemDetail};
283:[1m[91merror[E0423][0m[1m: expected function, tuple struct or tuple variant, found enum `Capability`[0m
308:[1m[91merror[E0423][0m[1m: expected function, tuple struct or tuple variant, found enum `Capability`[0m
321:[1m[91merror[E0423][0m[1m: expected function, tuple struct or tuple variant, found enum `Capability`[0m
392:[1m[91merror[E0599][0m[1m: no function or associated item named `new` found for struct `sha2::digest::core_api::CoreWrapper<T>` in the current scope[0m
