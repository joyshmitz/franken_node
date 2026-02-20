# RCH Execution Policy

**Owner bead:** bd-1dpd
**Status:** Active
**Policy version:** 1.0

## Purpose

CPU-intensive build, test, benchmark, and coverage workloads MUST execute via `rch` offload.
Direct local execution of classified commands is a policy violation.
This prevents resource contention under parallel multi-agent execution and ensures verification
results are reproducible, attributable, and audit-traceable.

## Command Classification

### rch-REQUIRED (fail-closed)

Any command matching these patterns MUST run through `rch exec` or the rch PreToolUse hook.

| Command class | Examples | rch kind |
|---|---|---|
| Cargo check | `cargo check`, `cargo check --all-targets` | CargoCheck |
| Cargo clippy | `cargo clippy`, `cargo clippy --all-targets` | CargoClippy |
| Cargo build | `cargo build`, `cargo build --release` | CargoBuild |
| Cargo test | `cargo test`, `cargo nextest run` | CargoTest |
| Cargo coverage | `cargo llvm-cov`, `cargo llvm-cov nextest` | CargoCoverage |
| Cargo bench | `cargo bench`, `criterion` | CargoBench |
| Broad E2E sweeps | Full-project E2E test orchestrators | E2ESweep |
| Miri | `cargo +nightly miri test` | CargoMiri |

### LOCAL-ALLOWED (no rch needed)

| Command class | Examples | Rationale |
|---|---|---|
| Cargo metadata | `cargo metadata`, `cargo tree` | Read-only, no compilation |
| Cargo fmt | `cargo fmt`, `cargo fmt --check` | Formatting only, sub-second |
| Cargo doc (check) | `cargo doc --no-deps` | Lightweight when not building deps |
| br / bv | `br list`, `bv -robot-priority` | Local tooling |
| Python scripts | `python3 scripts/*.py` | Linters, gates, validators |
| Shell scripts | `bash scripts/*.sh` | Lightweight verification |
| File operations | `cp`, `mv`, `mkdir`, `sha256sum` | No compilation |
| Git operations | `git status`, `git commit` | No compilation |

### EXCEPTION PROCESS

1. Add entry to `docs/verification/rch_exceptions.json` with:
   - `command_pattern`: glob pattern matching the command
   - `justification`: why local execution is acceptable
   - `approved_by`: agent or human approver name
   - `expires`: ISO 8601 expiry date (max 7 days)
2. Exceptions are logged as `RCH-POLICY-EXCEPTION` events.
3. Expired exceptions revert to fail-closed behavior.

## Enforcement Mechanism

### Hook-level (real-time)

The rch PreToolUse hook (`rch hook`) intercepts Bash tool calls and routes classified
commands to remote workers. This is the primary enforcement path.

### Gate-level (verification)

`scripts/verify_rch_required_workloads.sh` scans verification evidence artifacts for
provenance metadata. Any heavy workload result lacking rch provenance triggers a FAIL verdict.

### Evidence format

Every rch-offloaded run produces a provenance bundle:

```json
{
  "command": "cargo test --workspace",
  "rch_kind": "CargoTest",
  "worker_id": "vmi1264463",
  "worker_host": "worker-1.rch.internal",
  "queue_name": "default",
  "wait_duration_ms": 120,
  "run_duration_ms": 45200,
  "exit_code": 0,
  "timestamp": "2026-02-20T08:30:00Z",
  "policy_version": "1.0"
}
```

## Violation Semantics

| Severity | Condition | Action |
|---|---|---|
| VIOLATION | rch-required command run locally without exception | Gate FAIL, bead cannot close |
| WARNING | Exception used but nearing expiry | Log warning, no gate block |
| PASS | Command run via rch with valid provenance | Normal operation |

## Integration with Verification Gates

All section-wide and program-wide verification gates (`bd-3qsp` through `bd-unkm`)
consume the rch execution policy report as a required input dimension.
A FAIL verdict from this policy blocks the verification gate from passing.
