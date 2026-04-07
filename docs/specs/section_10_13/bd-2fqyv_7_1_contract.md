# bd-2fqyv.7.1 Contract: Fuzz Target Adapter and Truthful Execution/Reporting

## Scope

This contract defines the execution boundary that separates the named
deterministic fixture adapter from the truthful live fuzz gate so the fuzz
surface can be treated honestly.

The goal is to make implementation bead `bd-2fqyv.7.2` mechanical rather than
interpretive by answering these questions explicitly:

- how fuzz targets are discovered and selected
- what the adapter owns versus what gate aggregation owns
- how crashes, hangs, coverage, and infrastructure failures are classified
- what artifacts and report fields must exist for both local and remote runs

This contract refines, but does not replace:

- `docs/specs/section_10_13/bd-29ct_contract.md`
- `docs/governance/placeholder_surface_inventory.md` (`PSI-006`)

## Relationship to Existing Modules

- `crates/franken-node/src/connector/fuzz_corpus.rs` currently owns the
  modeling gate, seed registry, and error taxonomy.
- `scripts/check_placeholder_surface_inventory.py` enforces that the current
  synthetic markers remain confined to the named fixture adapter even after the
  real adapter exists.
- `bd-2fqyv.7.2` will replace the live execution path with a harness-backed
  runner while preserving deterministic fake adapters for tests.

The contract here is for the live adapter boundary. Deterministic simulations
may remain, but only behind explicit test/modeling interfaces that cannot be
confused with real fuzz evidence.

## Architectural Split

The future design has two layers:

1. `FuzzExecutionAdapter`
   - discovers runnable targets
   - prepares/stages seeds
   - invokes the real harness or remote execution backend
   - returns raw execution observations and artifact references
2. `FuzzGateAggregator`
   - validates configuration and target coverage
   - normalizes adapter output into deterministic report types
   - detects regressions/new crashes/untriaged outcomes
   - emits the final gate verdict and operator-facing artifacts

The adapter MUST NOT invent aggregate pass/fail claims. The aggregator MUST NOT
invent seed-level execution facts the adapter did not produce.

## Required Adapter Interface

The live adapter contract must expose at least these logical operations:

- `discover_targets(request) -> Vec<FuzzTargetDescriptor>`
- `prepare_campaign(target, seeds) -> PreparedCampaign`
- `execute_campaign(prepared_campaign) -> FuzzExecutionReport`
- `stage_artifacts(report) -> Vec<FuzzArtifactRef>`
- `health_snapshot() -> AdapterHealth`

The exact Rust trait shape is flexible, but the semantics are not.

## Target Discovery Contract

Every discovered target must carry deterministic metadata sufficient for
selection, execution, and reporting:

- `target_id`
- `category`
- `adapter_kind`
- `execution_ref`
- `working_directory`
- `timeout_policy`
- `coverage_mode`
- `supports_remote_execution`
- `supported_artifact_kinds`

Discovery MUST fail closed if any required target category is missing from the
requested live gate surface.

The adapter may discover targets from local binaries, harness manifests, or
remote registry metadata, but the returned target list must be stably sorted by
`target_id`.

## Seed Execution Contract

The adapter executes real seeds, not string-trigger heuristics.

For each seed, the adapter must return a `SeedExecutionResult` with at least:

- `target_id`
- `seed_id`
- `seed_digest`
- `started_at`
- `completed_at`
- `duration_ms`
- `outcome`
- `exit_detail`
- `crash_artifact`
- `hang_artifact`
- `coverage_artifacts`
- `artifact_refs`

`seed_id` must be stable for the campaign input. `seed_digest` must be derived
from the actual seed payload or canonical seed reference, not a display name.

## Outcome Taxonomy

Live execution must distinguish these states explicitly:

- `handled`
- `rejected`
- `crash`
- `hang`
- `infra_failed`
- `target_missing`
- `coverage_unavailable`

Rules:

- `crash` means the target or harness observed a real crash/panic/signal or an
  equivalent backend-reported crash outcome.
- `hang` means execution exceeded the declared timeout policy with enough
  evidence to distinguish it from queue delay or adapter outage.
- `infra_failed` means the adapter/harness/backend failed before producing a
  trustworthy target outcome.
- `coverage_unavailable` is not equivalent to `0.0` coverage. It means the
  campaign could not collect valid coverage evidence for a reason that must be
  recorded explicitly.

The implementation must never collapse infrastructure failure, missing target,
and target crash into one generic failure string.

## Coverage Semantics

`coverage_pct: 0.0` is not acceptable as a placeholder for missing evidence in
the live adapter path.

Coverage must be represented by explicit observation metadata:

- `coverage_pct: Option<f64>`
- `coverage_units` (edges, blocks, PCs, or adapter-defined equivalent)
- `coverage_source` (tool/runtime/backend)
- `coverage_scope` (per-seed, per-target, campaign aggregate)
- `coverage_status` (`measured`, `unavailable`, `unsupported`)
- `coverage_detail`

Rules:

- `measured` requires a finite numeric coverage value and provenance.
- `unsupported` is allowed only when the target/harness type genuinely cannot
  emit coverage and that limitation is declared in the target descriptor.
- `unavailable` means coverage was expected but collection failed; this is a
  real execution defect and must not be presented as successful coverage.

## Crash and Hang Triage Contract

Every `crash` or `hang` outcome must have triage-ready provenance:

- stable `seed_digest`
- target identifier
- reproduced command or execution reference
- stderr/stdout excerpt or equivalent backend detail
- artifact path/URI for the failing input or minimized reproducer
- crash/hang classifier

An issue remains `untriaged` only when the adapter cannot provide the minimum
reproducer bundle above. The gate must fail closed on untriaged crashes/hangs.

## Artifact Contract

The adapter must support both local and remotely-produced artifacts through the
same logical shape:

- `artifact_id`
- `artifact_kind`
- `artifact_uri` or local relative path
- `artifact_digest`
- `produced_by`
- `created_at`
- `is_remote`
- `retention_hint`

Required artifact kinds:

- reproducer seed/input
- crash or hang log
- coverage report or explicit coverage-status artifact
- campaign summary report

Paths written by local adapters must be relative to the campaign root or to a
declared output root. Remote adapters may use opaque URIs, but they still need
stable digests and provenance.

## Gate Aggregation Rules

The aggregator computes the final verdict from normalized adapter output.

Minimum rules:

- `PASS` only when every required target executed, no untriaged crash/hang
  occurred, no known regression was reintroduced, and required coverage
  evidence is either measured or explicitly unsupported.
- `FAIL` when any target crashes, hangs, regresses, or yields untriaged
  evidence.
- `ERROR` when the adapter cannot produce a trustworthy campaign result due to
  `infra_failed`, missing target discovery, malformed artifacts, or incomplete
  normalization.

The live gate must not translate `ERROR` into `PASS` or plain `FAIL` without
preserving the infrastructure provenance.

## Deterministic Fake Adapter Boundary

A deterministic fake adapter is still allowed for tests and modeling, but it
must be explicit.

Rules:

- fake adapters live behind a named test/modeling entrypoint
- fake adapters must not share the same constructor or default execution path
  as the live adapter
- fake output must clearly identify itself as synthetic
- placeholder scanner policy must continue treating the current synthetic
  `run_fixture_gate()` markers as allowlisted after the live adapter lands

This preserves reproducible tests without contaminating live evidence.

## Required Report Fields

The truthful gate report emitted by `bd-2fqyv.7.2` must include at least:

- `report_schema_version`
- `campaign_id`
- `adapter_kind`
- `targets_total`
- `targets_executed`
- `seeds_total`
- `seeds_executed`
- `targets: Vec<TargetExecutionSummary>`
- `triaged_failures: Vec<TriagedFailure>`
- `artifact_refs: Vec<FuzzArtifactRef>`
- `coverage_summary`
- `verdict`
- `error_detail`

Each `TargetExecutionSummary` must include:

- `target_id`
- `category`
- `outcome`
- `seeds_run`
- `crashes`
- `hangs`
- `coverage`
- `artifact_refs`
- `adapter_detail`

These fields are the minimum needed to distinguish real fuzz evidence from the
current synthetic stand-in.

## Required Verification For `bd-2fqyv.7.2`

Minimum coverage for the implementation bead:

- target discovery fails closed when a required category is missing
- live execution records real crash versus infra failure distinctly
- timeout/hang classification is explicit and testable
- coverage uses explicit availability semantics instead of hard-coded `0.0`
- triaged crash artifacts include a stable reproducer reference
- remote-produced artifacts normalize into the same report shape as local ones
- deterministic fake adapters remain available only through explicit test paths
- identical adapter output normalizes into byte-identical report payloads

## Non-Goals

- This contract does not mandate one specific fuzz engine forever.
- This contract does not require the current modeling helper to disappear
  immediately; it requires the live path to stop pretending the modeling helper
  is empirical execution.
- This contract does not decide long-term artifact retention policy beyond
  requiring stable identifiers, digests, and provenance.
