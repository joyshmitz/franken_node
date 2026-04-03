# Placeholder Surface Inventory

**Program:** `bd-2fqyv`  
**Bead:** `bd-2fqyv.1.1`  
**Status:** Active inventory for placeholder/demo/simulated production-surface remediation.

## Purpose

This document is the authoritative inventory of placeholder, demo, sample,
synthetic, skeleton, and simulated surfaces that matter to the current
remediation program.

It exists to answer three questions precisely:

1. Which surfaces are actually reachable from live operator-facing entrypoints?
2. Which simulations are acceptable because they are explicit test/modeling
   helpers rather than deceptive live behavior?
3. Which follow-on remediation bead owns each dangerous surface?

## Classification Rules

### `disallowed_live_shortcut`

The surface is reachable from a live CLI, script, exported operator flow, or
other production-facing path and currently manufactures attractive-but-fake
behavior. These paths must be removed or made fail-closed.

### `truthful_partial_surface`

The surface performs real work, but its real scope is materially narrower than
its product framing. The scope must be documented honestly and must not be
marketed or wired as a complete implementation until the missing behavior
exists.

### `deferred_skeleton`

The surface is intentionally not a live runtime yet. It may remain only if the
code and docs clearly describe it as a skeleton/deferred boundary and no live
operator path treats it as finished.

### `allowlisted_simulation`

The surface is an explicit test fixture, modeling helper, or self-test utility.
It is allowed only if it stays out of live operator/release paths and remains
clearly labeled as synthetic.

## Inventory

| ID | Classification | Surface | Entry points / files | Reachability | Current behavior | Remediation owner |
|---|---|---|---|---|---|---|
| `PSI-001` | `disallowed_live_shortcut` | Trust CLI demo registry | `crates/franken-node/src/main.rs` via `trust_card_cli_registry()`, `handle_trust_card_command(...)`; demo data from `crates/franken-node/src/supply_chain/trust_card.rs::demo_registry(...)` | Live CLI | `trust list`, `trust revoke`, `trust quarantine`, `trust sync`, and `trust-card *` commands operate on canned in-memory trust-card state rather than authoritative persisted state. Persistence/bootstrap contract is defined in `docs/specs/section_10_4/bd-2fqyv_2_1_contract.md`. | `bd-2fqyv.2` |
| `PSI-002` | `disallowed_live_shortcut` | Demo receipt signing in live CLI flows | `crates/franken-node/src/main.rs::maybe_export_demo_receipts(...)`; key material from `crates/franken-node/src/security/decision_receipt.rs::demo_signing_key(...)` | Live CLI | Trust and incident flows can export signed receipts using fixed demo key material, which makes outputs look operational without operator-managed trust roots. | `bd-2fqyv.3` |
| `PSI-003` | `disallowed_live_shortcut` | Incident bundle generated from sample events | `crates/franken-node/src/main.rs` `Command::Incident::Bundle`; helper `crates/franken-node/src/tools/replay_bundle.rs::sample_incident_events(...)` | Live CLI | `franken-node incident bundle` emits plausible replay bundles from hard-coded sample events instead of authoritative incident evidence. | `bd-2fqyv.4` |
| `PSI-004` | `deferred_skeleton` | Control-plane service skeleton with zeroed perf baselines | `crates/franken-node/src/api/service.rs`, `crates/franken-node/src/api/middleware.rs`; supporting docs in `docs/architecture/blueprint.md` and `docs/architecture/tri_kernel_ownership_contract.md` | Not a live server boundary | Route catalog, middleware, and endpoint reports exist, but the module explicitly does not own a real async HTTP/gRPC boundary and reports `0.0` latency baselines. This is allowed only as a documented skeleton. | Follow-on bead required under `bd-2fqyv` program; scanner policy under `bd-2fqyv.1.2` must keep it allowlisted until a real transport boundary exists. |
| `PSI-005` | `truthful_partial_surface` | Migration live surface is audit/manifest-rewrite only | `crates/franken-node/src/main.rs` `MigrateCommand::{Audit,Rewrite,Validate}`; implementation in `crates/franken-node/src/migration/mod.rs::{run_audit, run_rewrite, run_validate}` | Live CLI | Current migration behavior is real but narrow: audit, lockfile/script checks, `package.json` engine pinning, manual-review reporting, and validation gates. It is not a general state/data migration executor and must not be represented as one. | Follow-on remediation bead required under `bd-2fqyv`; scanner policy under `bd-2fqyv.1.2` should flag overclaims about full migration execution. |
| `PSI-006` | `allowlisted_simulation` | Fuzz gate simulation helper | `crates/franken-node/src/connector/fuzz_corpus.rs::run_gate(...)`; verified by `scripts/check_fuzz_corpus.py` | Library / verification only | Crashes are inferred from seed text containing `crash`, and coverage is hard-coded to `0.0`. This is acceptable only as an internal modeling helper until a live empirical fuzz runner exists. | Keep allowlisted for now; `bd-2fqyv.1.2` must fail if any live gate or operator path starts consuming it as real fuzz evidence. |
| `PSI-007` | `disallowed_live_shortcut` | Obligation guard drop path logs instead of rolling back | `crates/franken-node/src/connector/obligation_tracker.rs::ObligationGuard::drop(...)` | Library, safety-critical | The contract comment says dropping an unresolved guard triggers rollback, but the implementation only emits an `eprintln!` and relies on later leak detection. This is a deceptive safety shortcut, not a real rollback path. | Follow-on remediation bead required under `bd-2fqyv`; scanner policy under `bd-2fqyv.1.2` should flag log-only rollback claims. |
| `PSI-008` | `truthful_partial_surface` | Ecosystem health export contains placeholder values | `crates/franken-node/src/supply_chain/ecosystem_telemetry.rs::export_health(...)` | Library / export helper | `compromise_reduction_factor` is fixed at `1.0` and `certification_distribution` is empty even when an export is produced. This helper must not be treated as authoritative ecosystem health until live metrics are wired. | Follow-on remediation bead required under `bd-2fqyv`; scanner policy under `bd-2fqyv.1.2` should flag operator-facing consumers. |
| `PSI-009` | `truthful_partial_surface` | DGIS barrier pass receipts can be synthesized from placeholder barrier context | `crates/franken-node/src/security/dgis/barrier_primitives.rs::check_sandbox_escalation(...)` and `make_pass_receipt(...)` | Library / internal security primitive | The current pass path can construct a receipt from first-match-or-placeholder barrier context instead of proving that an authoritative live barrier produced the decision. This is unacceptable once promoted to evidence-bearing operator flows. | Follow-on remediation bead required under `bd-2fqyv`; scanner policy under `bd-2fqyv.1.2` should flag live consumers. |
| `PSI-010` | `disallowed_live_shortcut` | External reproduction script simulates claim verification | `scripts/reproduce.py::{verify_claim, run_reproduction}`; docs point to it from `docs/reproduction_playbook.md` and `docs/policy/external_reproduction.md` | Live operator script | The script currently emits `pass: true` with `verification simulated (full execution requires test harness)` instead of performing the referenced verification commands. | Follow-on remediation bead required under `bd-2fqyv`; scanner policy under `bd-2fqyv.1.2` should fail on simulated verification in live reproduction entrypoints. |

## Allowed Simulations

The following simulations are currently allowed because they are explicit
test/modeling helpers rather than deceptive live surfaces:

| Surface | Why it is allowed |
|---|---|
| `demo_registry(...)` inside unit tests in `crates/franken-node/src/supply_chain/trust_card.rs` and `crates/franken-node/src/api/trust_card_routes.rs` tests | Test-only fixture state used to exercise registry behavior; not acceptable in live CLI wiring. |
| `sample_incident_events(...)` when used by tests in `crates/franken-node/src/tools/replay_bundle.rs` | Deterministic fixture generation for replay-bundle tests; not acceptable in live incident evidence export. |
| `synthetic_bearer_admin_route()` in `crates/franken-node/src/api/service.rs` tests | Explicit negative test helper proving bearer auth cannot reach mTLS-only admin routes. |
| Python script self-tests that generate synthetic data (`scripts/check_*`, `scripts/project_scanner.py`, `scripts/e2e_test_server.py`) | Internal test harness behavior is acceptable when the script/docstring makes the synthetic nature explicit and no live operator contract treats the output as real evidence. |

## Inventory Notes

- Reachability matters more than keywords. A `demo_*` helper used only inside
  unit tests is not a program-level risk by itself.
- Skeletons are not automatically bugs. They become bugs when operator-facing
  flows, reports, or docs imply they are live, complete, or evidence-bearing.
- Truthful partial surfaces are allowed to exist temporarily, but only if their
  narrow real scope is documented explicitly and downstream consumers do not
  mistake them for completed product capabilities.

## Reproduction Procedure

The current inventory can be refreshed with focused searches like:

```bash
rg -n "demo_registry\\(|sample_incident_events\\(|demo_signing_key\\(|maybe_export_demo_receipts|trust_card_cli_registry" crates/franken-node/src
rg -n "service skeleton|real baselines|synthetic_bearer_admin_route" crates/franken-node/src/api
rg -n "run_rewrite|run_validate|engines.node|manual review" crates/franken-node/src/migration
rg -n "simulated crash|coverage_pct: 0.0" crates/franken-node/src/connector/fuzz_corpus.rs
rg -n "In a real implementation this would call tracker.rollback" crates/franken-node/src/connector/obligation_tracker.rs
rg -n "Placeholder|Populated from live data" crates/franken-node/src/supply_chain/ecosystem_telemetry.rs
rg -n "placeholder" crates/franken-node/src/security/dgis/barrier_primitives.rs
rg -n "verification simulated" scripts/reproduce.py
```

Downstream beads must update this inventory when they remove a shortcut or when
a currently allowlisted simulation becomes live-reachable.
