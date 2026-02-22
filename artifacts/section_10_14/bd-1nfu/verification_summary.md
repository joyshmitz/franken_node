# bd-1nfu Verification Summary

## Result
PASS (bead scope) with pre-existing workspace baseline cargo failures

## Delivered
- `crates/franken-node/src/security/remote_cap.rs`
- `crates/franken-node/src/security/mod.rs`
- `crates/franken-node/src/security/network_guard.rs`
- `crates/franken-node/src/cli.rs` (adds `remotecap issue` command surface)
- `crates/franken-node/src/main.rs` (adds issue handler + TTL/operation parsing)
- `docs/specs/remote_cap_contract.md`
- `tests/security/remote_cap_enforcement.rs`
- `artifacts/10.14/remote_cap_denials.json`
- `artifacts/section_10_14/bd-1nfu/check_report_takeover.json`
- `artifacts/section_10_14/bd-1nfu/verification_evidence.json`

## Commands
- `rch exec -- cargo test --manifest-path crates/franken-node/Cargo.toml remote_cap -- --nocapture`
- `rch exec -- cargo run --manifest-path crates/franken-node/Cargo.toml -- remotecap issue --scope network_egress,telemetry_export --endpoint https:// --ttl 15m --issuer ops-control-plane --operator-approved --json`
- `rch exec -- cargo check --all-targets`
- `rch exec -- cargo clippy --all-targets -- -D warnings`
- `rch exec -- cargo fmt --check`

## Key Outcomes
- `RemoteCap` remains provider-issued and centrally enforced for network-bound operations.
- `remotecap` CLI command surface is now explicitly wired: `franken-node remotecap issue ...`.
- CLI issuance flow now parses scoped operations, endpoint prefixes, TTL (`s/m/h/d`), and explicit operator authorization.
- Contract documentation now includes concrete CLI invocation with required flags.

## Cargo Gate Notes
- Targeted `remote_cap` test invocation currently exits `101` due unrelated workspace compile debt.
- CLI smoke invocation currently exits `101` due unrelated workspace compile debt.
- `cargo check --all-targets` exits `101` (pre-existing workspace compile debt).
- `cargo clippy --all-targets -- -D warnings` exits `101` (pre-existing workspace lint/compile debt).
- `cargo fmt --check` exits `1` (pre-existing formatting drift in unrelated files).
