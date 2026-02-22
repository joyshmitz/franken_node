# Semantic Oracle Policy (bd-al8i)

## Scope

This policy governs the L2 engine-boundary N-version semantic oracle that
compares `franken_engine` outputs against reference runtimes.  The oracle
classifies boundary divergences by risk tier and enforces release gates.

## Core Invariants

- `INV-ORACLE-HIGH-RISK-BLOCKS`: high-risk unresolved deltas block release.
  Any boundary where all reference runtimes agree on an output that differs
  from `franken_engine` is classified as high risk and prevents the release
  gate from passing.
- `INV-ORACLE-LOW-RISK-RECEIPTED`: low-risk and medium-risk deltas require
  explicit policy receipts.  Each receipt must include a justification, an
  issuer, and a valid L1 oracle result link.
- `INV-ORACLE-DETERMINISTIC-CLASSIFICATION`: the classification algorithm is
  deterministic.  Given identical inputs the risk tier assignment is always
  the same.
- `INV-ORACLE-L1-LINKAGE`: every policy receipt must link back to an L1
  product-oracle result.  Receipts with empty or broken links cause the
  release gate to block.

## Risk Tiers

| Tier   | Condition                                              | Action                          |
|--------|--------------------------------------------------------|---------------------------------|
| High   | All references agree, franken_engine disagrees         | Release blocked unconditionally |
| Medium | References themselves disagree, or single reference    | Receipt required                |
| Low    | Outputs match                                          | No action (no divergence)       |

## Event Codes

- `ORACLE_HARNESS_START` -- emitted when the differential harness begins.
- `ORACLE_DIVERGENCE_CLASSIFIED` -- emitted for each classified divergence.
- `ORACLE_RISK_TIER_ASSIGNED` -- emitted when a risk tier is assigned.
- `ORACLE_RELEASE_BLOCKED` -- emitted when the release gate blocks.
- `ORACLE_POLICY_RECEIPT_ISSUED` -- emitted when a receipt covers a delta.

## Error Codes

- `ERR_ORACLE_HIGH_RISK_DELTA` -- high-risk unresolved divergence.
- `ERR_ORACLE_MISSING_RECEIPT` -- low/medium-risk delta with no receipt.
- `ERR_ORACLE_HARNESS_TIMEOUT` -- harness execution exceeded time limit.
- `ERR_ORACLE_REFERENCE_UNAVAILABLE` -- no reference runtimes configured.
- `ERR_ORACLE_CLASSIFICATION_AMBIGUOUS` -- classifier cannot assign tier.
- `ERR_ORACLE_L1_LINK_BROKEN` -- receipt L1 link is empty or invalid.

## Policy Receipt Schema

Required fields:

- `receipt_id`
- `divergence_id`
- `risk_tier`
- `justification`
- `l1_oracle_result_link`
- `issuer`
- `issued_epoch_ms`

## Differential Harness Workflow

1. Configure `HarnessConfig` with at least one `ReferenceRuntime`.
2. Collect `BoundarySample` entries for each engine-boundary interface.
3. Run `run_harness()` to produce `OracleResult`.
4. For each low/medium divergence, supply a `PolicyReceipt`.
5. Re-run harness to confirm all non-high-risk deltas are receipted.
6. Release gate passes only when `verdict == Passed`.

## Implementation

- Rust module: `crates/franken-node/src/connector/n_version_oracle.rs`
- Check script: `scripts/check_semantic_oracle.py`
- Report artifact: `artifacts/10.17/semantic_oracle_report.json`
- Divergence matrix: `artifacts/10.17/semantic_oracle_divergence_matrix.csv`

## Traceability

- Section: 10.17
- Bead: bd-al8i
- L1 dependency: L1 product-oracle results (linked via receipt `l1_oracle_result_link`)
