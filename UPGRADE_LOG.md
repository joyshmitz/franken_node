# Dependency Upgrade Log — franken_node

**Date:** 2026-04-21
**Language:** Rust (edition 2024, nightly toolchain)
**Workspace:** 2 members (`crates/franken-node`, `sdk/verifier`) + separate `fuzz/` build

## Summary

- **Updated (registry switch):** 1 direct (`asupersync`) + 4 transitive (`asupersync-macros`, `franken-kernel`, `franken-decision`, `franken-evidence`) from local path deps to crates.io 0.3.1
- **Updated (lockfile, semver-compat):** 19 transitive bumps via `cargo update`
- **Skipped (major bump — needs user authorization):** `sha2` 0.10.9 → 0.11.0 in `sdk/verifier` and `frankenengine-node` (169 call sites in main crate, 2 in sdk/verifier)
- **At latest:** everything else — `chrono` 0.4.44, `clap` 4.6.1, `uuid` 1.23.1, `tempfile` 3.27.0, `rustls` 0.23.38, `wasm-bindgen` 0.2.118, etc.

## Updates

### asupersync: path="/dp/asupersync" → 0.3.1 (crates.io)

- **Breaking:** None at call sites.
- **Motivation:** Made workspace buildable from fresh clone; previously required sibling `/data/projects/asupersync` checkout. 0.3.1 is the first crates.io release with the stable `Cx`/region-based runtime API we consume via `asupersync-transport` feature.
- **File:** `crates/franken-node/Cargo.toml`
- **Tests:** `cargo check --features asupersync-transport -p frankenengine-node` clean (only pre-existing `unused import: write_bundle_to_path` warning in main.rs:136).
- **Commit:** `92a10d64` (`deps: switch asupersync from local path to crates.io 0.3.1`)

### cargo update — 19 transitive bumps, no manifest edits

- `syn` 2.0.116 → 2.0.117 (dev)
- `uuid` 1.21.0 → 1.23.1 (direct spec `"1.16.0"` allowed it)
- `tempfile` 3.25.0 → 3.27.0
- `tracing-subscriber` 0.3.22 → 0.3.23
- `rustls` 0.23.37 → 0.23.38, `rustls-webpki` 0.103.10 → 0.103.13 (security patches)
- `semver` 1.0.27 → 1.0.28
- `simd-adler32` 0.3.8 → 0.3.9
- `typenum` 1.19.0 → 1.20.0
- `winnow` 0.7.14 → 0.7.15
- `webpki-roots` 1.0.6 → 1.0.7 (trust store refresh)
- `wasm-bindgen` 0.2.109 → 0.2.118 (+ futures 0.4.68, macro-support, shared)
- `web-sys` 0.3.86 → 0.3.95
- `wasip2` 1.0.2 → 1.0.3
- `wit-bindgen` 0.57.1 added
- `chrono` resolved at 0.4.44 (spec `"0.4.40"` already allowed)
- `clap` resolved at 4.6.1 (spec `"4.5.32"` already allowed)

6 deps remain "behind latest" because of compat constraints elsewhere in the graph (cargo's note — not bugs).

- **Tests:** `cargo check --features asupersync-transport -p frankenengine-node` clean.
- **Commit:** `fad828c3` (`deps: cargo update within semver (transitive lockfile refresh)`)

## Needs Attention — requires user decision

### sha2: 0.10.9 → 0.11.0 (MAJOR)

- **Scope:** Breaking API. RustCrypto 0.11 digest trait family (aligned with `digest` 0.11, `block-buffer` 0.12, `crypto-common` 0.2).
- **Call sites in franken_node:**
  - `crates/franken-node/`: **169 files** use `sha2::` / `Sha256::new()` / `Sha512::new()`.
  - `sdk/verifier/`: **2 files** (`bundle.rs`, `capsule.rs`).
- **Circuit breaker triggered** (>20-file refactor): deferred pending explicit authorization.
- **Note:** `asupersync-transport` feature already pulls in `sha2 0.11.0` transitively via `franken-kernel` 0.3.1 — it coexists with the direct `sha2 0.10.9` in Cargo.lock. Bumping the direct dep to 0.11 collapses the duplication but requires source-level API migration across all 171 call sites.

## Skipped / Preserved

- `frankentui` — path dep (workspace crate in `/dp/frankentui/crates/ftui`); not on crates.io.
- `frankenengine-engine`, `frankenengine-extension-host` — path deps to sibling `franken_engine` workspace.
- `fsqlite` — path dep to sibling `/dp/frankensqlite` workspace.
- `ureq = "2"`, `url = "2.5"`, `ctrlc = "3"` — broad specs, cargo update kept them within their major.

## Environment

- Verified build host: Ubuntu 24.04 LTS, Linux 6.17.0-22-generic
- Toolchain: rustc 1.95.0-nightly (7f99507f5 2026-02-19)
- Build dir override: `CARGO_TARGET_DIR=/data/tmp/franken_node_target` (root `target/` is immutable on this host — `sbh` disk-pressure guard)
- `cargo audit` not run yet (deferred; wire into CI before the 0.11 sha2 migration).
