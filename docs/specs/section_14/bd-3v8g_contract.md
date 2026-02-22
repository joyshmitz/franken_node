# bd-3v8g: Version Benchmark Standards with Migration Guidance

**Section:** 14 — Benchmark + Standardization
**Status:** Implemented
**Module:** `crates/franken-node/src/tools/version_benchmark_standards.rs`

## Purpose

Manages versioned benchmark standard definitions with explicit migration paths between revisions. Ensures reproducibility by embedding version identifiers in every benchmark artifact and providing machine-readable migration guides when standards evolve.

## Standard Revisions (3 initial)

| Version | Title | Tracks |
|---------|-------|--------|
| 1.0.0 | Initial benchmark standard | 6 |
| 1.1.0 | Add trust co-metrics tracks | 7 |
| 2.0.0 | Restructured scoring with verifier toolkit | 8 |

## Compatibility Levels (4)

| Level | Description |
|-------|-------------|
| FullyCompatible | No changes needed |
| BackwardCompatible | New features, old configs still work |
| RequiresMigration | Breaking changes, explicit migration required |
| Incompatible | Cannot migrate without full rewrite |

## Change Types (4)

| Type | Description |
|------|-------------|
| Breaking | Incompatible API/schema changes |
| Feature | New backward-compatible functionality |
| Fix | Bug fixes |
| Deprecation | Feature marked for future removal |

## Migration Effort Levels (4)

| Level | Description |
|-------|-------------|
| Trivial | No manual work needed |
| Low | Minor configuration update |
| Medium | Multiple manual steps |
| High | Significant rework required |

## Gate Behavior

- All versions follow semantic versioning (major.minor.patch)
- Breaking changes (major version bump) require migration acknowledgment
- Migration guides include step-by-step instructions with automated/manual classification
- Content hash ensures guide integrity and determinism
- Rollback is possible for non-incompatible migrations

## Invariants

| Invariant | Description |
|-----------|-------------|
| INV-BSV-SEMVER | All standard versions follow semantic versioning |
| INV-BSV-DETERMINISTIC | Same version inputs produce same migration output |
| INV-BSV-MIGRATION-PATH | Every adjacent version pair has a migration guide |
| INV-BSV-BACKWARD-COMPAT | Non-breaking changes preserve backward compatibility |
| INV-BSV-VERSIONED | Standard version embedded in every benchmark artifact |
| INV-BSV-GATED | Breaking changes require explicit migration acknowledgment |

## Event Codes

| Code | Meaning |
|------|---------|
| BSV-001 | Revision registered |
| BSV-002 | Migration computed |
| BSV-003 | Compatibility checked |
| BSV-004 | Guide generated |
| BSV-005 | Breaking change detected |
| BSV-006 | Version compared |
| BSV-007 | Report generated |
| BSV-008 | Deprecation noticed |
| BSV-009 | Rollback computed |
| BSV-010 | Standard locked |
| BSV-ERR-001 | Invalid version |
| BSV-ERR-002 | No migration path |

## Test Coverage

- 30 Rust inline tests covering semantic versioning, migration computation, compatibility checks, effort estimation, report generation, audit logging, and custom revision registration
- Python verification gate checks
- Python unit tests
