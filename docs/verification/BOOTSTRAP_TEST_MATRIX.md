# Bootstrap Foundation Test Matrix

**Owner bead:** bd-jvzc
**Dependents:** bd-3k9t (foundation e2e scripts)
**Matrix version:** 1.0

## Purpose

Defines the complete test matrix for bootstrap capabilities (CLI, configuration,
transplant integrity, operator diagnostics) with deterministic fixture contracts.
Each test family maps to an owning bead and is consumed by the bootstrap verification gate.

## Test Families

### TF-CLI: CLI Bootstrap

**Owning beads:** bd-2lb (clap surface), bd-n9r (config system)

| ID | Scenario | Path type | Input fixture | Expected output | Seed |
|---|---|---|---|---|---|
| TF-CLI-001 | `franken-node --version` | Happy | none | version string on stdout, exit 0 | — |
| TF-CLI-002 | `franken-node --help` | Happy | none | usage text on stdout, exit 0 | — |
| TF-CLI-003 | `franken-node unknown-subcommand` | Error | none | error message on stderr, exit 2 | — |
| TF-CLI-004 | `franken-node --config missing.toml` | Error | `cli/missing_config.toml` (absent) | config-not-found error, exit 1 | — |
| TF-CLI-005 | `franken-node` (no args, no config) | Edge | none | default behavior or help, exit 0 | — |
| TF-CLI-006 | `franken-node --config valid.toml` | Happy | `cli/valid_config.toml` | config loaded successfully, exit 0 | — |
| TF-CLI-007 | `franken-node --config malformed.toml` | Adversarial | `cli/malformed_config.toml` | parse error with line number, exit 1 | — |

### TF-CONFIG: Configuration Resolution

**Owning beads:** bd-n9r (config system)

| ID | Scenario | Path type | Input fixture | Expected output | Seed |
|---|---|---|---|---|---|
| TF-CONFIG-001 | Default config resolution | Happy | none (uses built-in defaults) | default profile active | — |
| TF-CONFIG-002 | Profile override via env var | Happy | `config/env_override.env` | env profile values override defaults | — |
| TF-CONFIG-003 | Profile override via CLI flag | Happy | `config/base.toml` + `--profile dev` | dev profile merged over base | — |
| TF-CONFIG-004 | Precedence: CLI > env > file > default | Edge | `config/precedence_stack/` | CLI value wins | — |
| TF-CONFIG-005 | Unknown profile name | Error | `config/base.toml` + `--profile nonexistent` | profile-not-found error | — |
| TF-CONFIG-006 | Empty config file | Edge | `config/empty.toml` | defaults used, no crash | — |
| TF-CONFIG-007 | Config with extra unknown keys | Edge | `config/extra_keys.toml` | warning on stderr, valid keys parsed | — |
| TF-CONFIG-008 | Config with type mismatch | Adversarial | `config/type_mismatch.toml` | type error with field path | — |

### TF-TRANSPLANT: Transplant Integrity

**Owning beads:** bd-1qz (restore), bd-7rt (lockfile), bd-29q (drift/resync)

| ID | Scenario | Path type | Input fixture | Expected output | Seed |
|---|---|---|---|---|---|
| TF-TRANSPLANT-001 | Lockfile verification PASS | Happy | `transplant/golden_snapshot/` | PASS verdict, 0 mismatches | — |
| TF-TRANSPLANT-002 | Lockfile verification MISMATCH | Error | `transplant/tampered_snapshot/` | FAIL:MISMATCH, identifies changed file | — |
| TF-TRANSPLANT-003 | Lockfile verification MISSING | Error | `transplant/incomplete_snapshot/` | FAIL:MISSING, lists absent files | — |
| TF-TRANSPLANT-004 | Lockfile verification EXTRA | Edge | `transplant/extra_files_snapshot/` | FAIL:EXTRA or warning, lists extras | — |
| TF-TRANSPLANT-005 | Drift detection clean | Happy | `transplant/synced_pair/` | 0 drift categories | — |
| TF-TRANSPLANT-006 | Drift detection content change | Error | `transplant/drifted_pair/` | CONTENT_DRIFT detected | — |
| TF-TRANSPLANT-007 | Re-sync dry run | Edge | `transplant/drifted_pair/` | plan output, no files changed | — |
| TF-TRANSPLANT-008 | Lockfile determinism | Happy | `transplant/golden_snapshot/` | regenerated lockfile byte-identical | — |
| TF-TRANSPLANT-009 | Empty snapshot directory | Adversarial | `transplant/empty_dir/` | graceful error, not crash | — |

### TF-DIAG: Operator Diagnostics

**Owning beads:** bd-2a3 (workspace checks)

| ID | Scenario | Path type | Input fixture | Expected output | Seed |
|---|---|---|---|---|---|
| TF-DIAG-001 | Workspace health check pass | Happy | valid Cargo.toml workspace | all checks green | — |
| TF-DIAG-002 | Missing Cargo.toml | Error | absent workspace | clear error message | — |
| TF-DIAG-003 | Rust toolchain check | Happy | nightly toolchain installed | toolchain version reported | — |
| TF-DIAG-004 | rch connectivity check | Happy | rch daemon running | rch status green | — |
| TF-DIAG-005 | rch not available | Edge | rch daemon stopped | clear degraded-mode warning | — |

## Fixture Contract

### Deterministic rules

1. All fixtures use fixed seeds where randomness is involved.
2. No system clock dependency — timestamps are injected via fixtures.
3. File paths in fixtures use relative paths from the fixture root.
4. Expected outputs are byte-exact JSON (pretty-printed, sorted keys).

### Fixture directory layout

```
tests/fixtures/bootstrap/
  cli/
    valid_config.toml
    malformed_config.toml
  config/
    base.toml
    env_override.env
    empty.toml
    extra_keys.toml
    type_mismatch.toml
    precedence_stack/
  transplant/
    golden_snapshot/
    tampered_snapshot/
    incomplete_snapshot/
    extra_files_snapshot/
    synced_pair/
    drifted_pair/
    empty_dir/
  diag/
    (uses live workspace state, no fixtures needed)
```

### Replay instructions

```bash
# Run entire bootstrap test matrix
python3 scripts/run_bootstrap_test_matrix.py

# Run single test family
python3 scripts/run_bootstrap_test_matrix.py --family TF-CLI

# Run single test
python3 scripts/run_bootstrap_test_matrix.py --test TF-CLI-001
```

## Gate Consumption

The bootstrap verification gate (bd-3ohj) consumes this matrix by:
1. Running all test families in deterministic order.
2. Collecting pass/fail/skip counts per family.
3. Emitting a machine-readable evidence artifact at:
   `artifacts/bootstrap/bootstrap/gate_verdict/bd-3ohj_bootstrap_gate.json`
