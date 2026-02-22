# bd-1tnu: Trust Barrier Primitives and Policy Wiring

**Section:** 10.20 — Dependency Graph Immune System (Enhancement Map 9N)
**Track:** DGIS Enforcement Layer
**Status:** Active

## Purpose

Implements the runtime enforcement layer for the DGIS immunization planner.
Four categories of trust barrier primitives protect dependency-graph choke
points with deterministic semantics, composability, operator overrides, and
full audit trails.

## Barrier Categories

### 1. Behavioral Sandbox Escalation

Dynamically tightens sandbox constraints on nodes flagged as high-risk.

- **SandboxTier**: None, Basic, Standard, Strict, Maximum (ordered escalation)
- Nodes have a minimum tier floor; escalation raises the floor
- Denied capabilities are blocked when tier is active
- De-escalation requires explicit operator action with justification

### 2. Composition Firewall

Prevents transitive capability leakage across dependency boundaries.

- Blocks specified capabilities from crossing a named boundary
- Optional allow-list for known-safe cross-boundary flows
- Boundary-scoped: each firewall applies to a specific subgraph partition

### 3. Verified-Fork Pinning

Locks dependencies to verified fork snapshots with signature verification.

- Each pin specifies: fork source URL, commit digest (SHA-256), maintainer
- On load, the actual dependency digest is computed and compared
- Mismatches produce `DGIS-BARRIER-031` (fork pin rejected) and block activation

### 4. Staged Rollout Fences

Gates dependency updates through progressive deployment phases.

- Phases: Canary, Limited, General, Complete (ordered progression)
- Each phase requires minimum observations and failure-rate thresholds
- Auto-rollback to Canary on failure threshold breach
- Only one rollout fence per node per version (conflict detection)

## Composability

Multiple barriers can be applied to the same node:
- Barriers are evaluated in type-priority order
- Composition conflicts (e.g., two rollout fences on one node) are detected and rejected
- Combined enforcement produces a single deny/allow decision

## Override Mechanism

Operators can override barriers with signed justification:
- Override requires: principal identity, justification text, optional expiry
- Override justification must be non-empty
- Every override emits an audit receipt with principal attribution
- Overrides without valid justification are rejected with `DGIS-BARRIER-ERR-002`

## Audit Receipts

Every barrier enforcement action produces a signed receipt:
- Fields: id, node_id, barrier_type, action, timestamp, principal, justification, content_hash
- Content hash is deterministic (SHA-256 over canonical fields)
- Receipts export as JSONL for post-hoc audit and replay
- Trace correlation IDs link enforcement to barrier plans

## Event Codes

| Code | Description |
|------|-------------|
| `DGIS-BARRIER-001` | Barrier applied to node |
| `DGIS-BARRIER-002` | Barrier removed from node |
| `DGIS-BARRIER-003` | Barrier overridden by operator |
| `DGIS-BARRIER-004` | Barrier expired |
| `DGIS-BARRIER-005` | Barrier check passed |
| `DGIS-BARRIER-006` | Barrier check denied |
| `DGIS-BARRIER-010` | Sandbox tier escalated |
| `DGIS-BARRIER-020` | Composition firewall enforced |
| `DGIS-BARRIER-030` | Fork pin verified successfully |
| `DGIS-BARRIER-031` | Fork pin rejected (digest mismatch) |
| `DGIS-BARRIER-040` | Rollout fence advanced to next phase |
| `DGIS-BARRIER-041` | Rollout fence blocked advancement |
| `DGIS-BARRIER-042` | Rollout fence rolled back |
| `DGIS-BARRIER-ERR-001` | Barrier composition conflict |
| `DGIS-BARRIER-ERR-002` | Invalid override (missing justification) |

## Policy Engine

The `BarrierPolicyEngine` translates barrier plans from the immunization planner
into runtime enforcement:
- Accepts a `BarrierPlan` (list of barrier configs per node)
- Applies barriers to the node registry
- Traces source plan ID for auditability

## Acceptance Criteria

1. Each of the 4 barrier types has independent test coverage.
2. Composition of 2+ barriers on a single node produces deterministic combined enforcement.
3. Override mechanism requires signed justification and emits audit receipt.
4. Audit receipts are structured, timestamped, and include principal identity.
5. Content hashes are deterministic and verifiable.
6. Rollout fence detects conflicts (two fences on same node).
7. Fork pin verifies digest and rejects mismatches.
8. Sandbox escalation enforces minimum tier and denied capabilities.
9. Firewall blocks cross-boundary capability leakage.
10. Policy engine applies barrier plans from immunization planner.

## Artifacts

- `crates/franken-node/src/security/dgis/barrier_primitives.rs` — Rust implementation
- `crates/franken-node/src/security/dgis/mod.rs` — module wiring
- `scripts/check_dgis_barrier.py` — verification script
- `tests/test_check_dgis_barrier.py` — Python unit tests
- `artifacts/section_10_20/bd-1tnu/verification_evidence.json` — CI evidence
- `artifacts/section_10_20/bd-1tnu/verification_summary.md` — human summary

## Dependencies

- None (standalone primitive layer).
- Depended on by: bd-3po7 (section gate), bd-ybe (plan tracker).
