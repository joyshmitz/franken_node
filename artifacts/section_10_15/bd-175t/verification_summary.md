# bd-175t verification summary

## Scope
Validate that `cx_first_api_gate` no longer hard-fails on rch workers that do not have the `ast-grep` binary installed.

## Pre-fix reproduction (failure)
- Command: `rch exec -- cargo test -p frankenengine-node --test cx_first_api_gate -- --nocapture`
- Evidence: `rch_cx_first_api_gate_pre_fix.log`, `rch_cx_first_api_gate_pre_fix.exit`
- Result: failed with `Io(NotFound)` from policy scanner subprocess launch.

## Post-fix verification (success)
- Command: `rch exec -- env CARGO_TARGET_DIR=target/rch_bd175t_postfix cargo test -p frankenengine-node --test cx_first_api_gate -- --nocapture`
- Evidence: `rch_cx_first_api_gate_post_fix.log`, `rch_cx_first_api_gate_post_fix.exit`
- Result: PASS (`7 passed; 0 failed`) including `falls_back_to_syn_when_ast_grep_binary_missing`.

## Notes
- A prior post-fix attempt stalled on a shared artifact lock; captured in `rch_cx_first_api_gate_post_fix_stalled.log`.
- All cargo test execution was run through `rch` per project policy.
