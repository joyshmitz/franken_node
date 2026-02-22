---
schema_version: "1.0"
bead_id: "bd-1id0"
section: "10.15"
kernels:
  franken_engine:
    plane: execution
    owns:
      - runtime execution internals
      - extension host sandbox boundary
      - low-level remote/effect execution primitives
  asupersync:
    plane: correctness-control
    owns:
      - cancellation protocol semantics
      - lane scheduling discipline
      - epoch transition barriers
      - deterministic replay/evidence contracts
  franken_node:
    plane: product
    owns:
      - user/operator product surfaces
      - policy orchestration and UX
      - evidence consumption and publication
hard_runtime_invariant_owners:
  HRI-01: asupersync
  HRI-02: asupersync
  HRI-03: asupersync
  HRI-04: asupersync
  HRI-05: asupersync
  HRI-06: asupersync
  HRI-07: asupersync
  HRI-08: asupersync
  HRI-09: asupersync
  HRI-10: franken_node
permitted_cross_kernel_interfaces:
  - "franken_node -> asupersync: Cx/Region/Epoch stable facades only"
  - "franken_node -> franken_engine: public runtime API only"
  - "asupersync -> franken_engine: explicit execution adapters only"
  - "no kernel may import another kernel's *_internal modules"
canonical_asupersync_primitives:
  - cx_propagation
  - region_ownership_scope
  - cancellation_protocol
  - obligation_tracking
  - remote_computation_registry
  - epoch_validity_window
  - evidence_ledger_emission
waiver_policy:
  registry_path: "docs/governance/ownership_boundary_waivers.json"
  required_fields:
    - waiver_id
    - file
    - boundary
    - rationale
    - signed_by
    - signature
    - expires_at
  expiry_enforced: true
  unsigned_allowed: false
structured_event_codes:
  - OWN-001
  - OWN-002
  - OWN-003
  - OWN-004
---

# Tri-Kernel Ownership Contract

## Scope

This contract defines hard ownership boundaries between:

- `franken_engine` (execution kernel)
- `asupersync` (correctness/control kernel)
- `franken_node` (product kernel)

Boundary violations are CI-fatal unless covered by a signed, non-expired waiver in
`docs/governance/ownership_boundary_waivers.json`.

## Ownership Planes

### Execution Plane (`franken_engine`)

Responsibilities:

- Runtime internals and low-level execution behavior
- Extension host isolation and sandbox substrate
- Primitive remote/effect execution mechanisms

Prohibited from:

- Embedding product UX/policy semantics
- Re-defining correctness-level cancellation/epoch protocol rules

### Correctness/Control Plane (`asupersync`)

Responsibilities:

- Cancellation protocol (`request -> drain -> finalize`)
- Scheduler lane semantics and starvation policy
- Epoch barriers and transition safety
- Deterministic evidence/replay correctness contracts

Prohibited from:

- Implementing product UX orchestration directly
- Bypassing execution kernel public interfaces

### Product Plane (`franken_node`)

Responsibilities:

- Product APIs, operator workflows, diagnostics, and reporting
- Policy orchestration over correctness/execution APIs
- Publication and governance surfaces

Prohibited from:

- Re-implementing execution primitives from `franken_engine`
- Re-implementing correctness protocol internals from `asupersync`

## Boundary Rules

1. Product code may consume correctness behavior only via approved facade APIs.
2. Product code may consume execution behavior only via approved execution APIs.
3. Direct imports into internal correctness/execution implementation modules are violations.
4. Duplicate implementation of ownership-scoped capabilities across kernels is prohibited.
5. Any exception requires a signed waiver with explicit expiry.

## Canonical Primitive Vocabulary

The canonical primitive list used by workflow-mapping gates is declared in frontmatter under
`canonical_asupersync_primitives` and currently includes:

- `cx_propagation`
- `region_ownership_scope`
- `cancellation_protocol`
- `obligation_tracking`
- `remote_computation_registry`
- `epoch_validity_window`
- `evidence_ledger_emission`

## Waiver Contract

A waiver record MUST include:

- `waiver_id` (stable identifier)
- `file` (project-relative path)
- `boundary` (e.g., `product->correctness-internal`)
- `rationale`
- `signed_by` (human approver)
- `signature` (non-empty approval proof string)
- `expires_at` (RFC 3339 date-time)

Unsigned or expired waivers fail CI (`OWN-004`).

## Structured Events

- `OWN-001`: boundary check pass
- `OWN-002`: boundary violation detected
- `OWN-003`: valid waiver applied
- `OWN-004`: waiver invalid or expired

## CI Enforcement

Primary gate artifact:

- `artifacts/10.15/ownership_boundary_report.json`

Conformance test surface:

- `tests/conformance/ownership_boundary_checks.rs`

Section evidence outputs:

- `artifacts/section_10_15/bd-1id0/verification_evidence.json`
- `artifacts/section_10_15/bd-1id0/verification_summary.md`
