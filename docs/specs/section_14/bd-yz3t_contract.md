# bd-yz3t: Verifier Toolkit for Independent Validation

**Section:** 14 — Benchmark + Standardization
**Status:** Implemented
**Module:** `crates/franken-node/src/tools/verifier_toolkit.rs`

## Purpose

Enables external parties to independently validate franken_node's benchmark claims, security metrics, and trust properties. Consumes benchmark specs (bd-3h1g) and security/trust co-metrics (bd-wzjl) to produce reproducible, machine-verifiable validation reports.

## Claim Types (5)

| Type | Label | Description |
|------|-------|-------------|
| `BenchmarkPerformance` | benchmark_performance | Runtime benchmark claims |
| `SecurityPosture` | security_posture | Security metric claims |
| `TrustProperty` | trust_property | Trust verification claims |
| `CompatibilityGuarantee` | compatibility_guarantee | API compatibility claims |
| `MigrationReadiness` | migration_readiness | Migration capability claims |

## Verdict Types

| Verdict | Condition |
|---------|-----------|
| `Pass` | All claims pass all 4 steps |
| `Fail` | All claims have at least one failure |
| `Partial` | Mix of passing and failing claims |

## Validation Steps (4 per claim)

| Step | Description |
|------|-------------|
| Schema validation | Validates claim structure and required fields |
| Evidence hash verification | Verifies SHA-256 evidence hash integrity |
| Metrics threshold check | Confirms all metrics meet declared thresholds |
| Cross-validation | Cross-checks metric consistency and bounds |

## Gate Behavior

- Claims must pass all 4 validation steps to be accepted
- Evidence hash must be 64-char lowercase hex (SHA-256)
- Metrics must be non-negative; thresholds must be in [0, 1]
- Evidence chain links all validation steps via parent hashes
- Content hash ensures report integrity
- Toolkit version embedded in every report

## Invariants

| Invariant | Description |
|-----------|-------------|
| INV-VTK-SCHEMA | All claims validated against published schema |
| INV-VTK-DETERMINISTIC | Same claim set produces same validation report |
| INV-VTK-EVIDENCE-CHAIN | Every validation step produces linkable evidence |
| INV-VTK-INDEPENDENT | No internal-only data required for validation |
| INV-VTK-VERSIONED | Toolkit version embedded in every report |
| INV-VTK-GATED | Validation failures block claim publication |

## Event Codes

| Code | Meaning |
|------|---------|
| VTK-001 | Claim ingested |
| VTK-002 | Schema validated |
| VTK-003 | Benchmark verified |
| VTK-004 | Metric cross-checked |
| VTK-005 | Evidence chain verified |
| VTK-006 | Report generated |
| VTK-007 | Claim rejected |
| VTK-008 | Regression detected |
| VTK-009 | Integrity computed |
| VTK-010 | Version recorded |
| VTK-ERR-001 | Validation error |
| VTK-ERR-002 | Schema error |

## Test Coverage

- 30 Rust inline tests covering schema validation, evidence verification, metric thresholds, cross-checks, full validation, report structure, evidence chain, confidence intervals, audit logging, and configuration
- Python verification gate checks
- Python unit tests
