# Frankensqlite Conformance Golden Files Provenance

## Generation Method

These golden files were extracted from the existing `canonical_classes()` function in 
`tests/integration/frankensqlite_adapter_conformance.rs` and converted to the 
structured format required for proper conformance testing.

## Source Data

- **Original Source**: `canonical_classes()` function (lines 638-875)
- **Contract Reference**: bd-1a1j persistence class contract
- **Extraction Date**: 2026-04-21T12:00:00Z
- **Total Classes**: 21 persistence classes
- **Tier Distribution**: 11 Tier1, 9 Tier2, 1 Tier3

## Golden Files

### persistence_class_catalog.json
- **Purpose**: Complete catalog of all persistence classes from bd-1a1j contract
- **Source**: Direct extraction from `canonical_classes()` hardcoded data
- **Structure**: Full class definitions with domains, modules, tables, replay strategies
- **Deterministic Fields**: All timestamps fixed to 2026-04-21T12:00:00Z

### tier_matrix.json
- **Purpose**: Safety tier definitions and durability mode mappings
- **Source**: Extracted from `SafetyTier` and `DurabilityMode` enum implementations
- **Compliance Rules**: Derived from existing test assertions in the conformance file
- **Structure**: Tier properties, durability constraints, compliance requirements

### adapter_conformance_report.json
- **Purpose**: Expected conformance test report structure
- **Source**: Synthesized from existing test patterns and requirements
- **Test Cases**: Derived from current individual test functions
- **Scrubbed Fields**: Template showing which fields get scrubbed in real runs

### event_log.json
- **Purpose**: Expected adapter event emission structure
- **Source**: Based on `FRANKENSQLITE_ADAPTER_INIT` and other event patterns
- **Event Types**: Covers adapter lifecycle, operations, and conformance verification
- **Scrubbed Fields**: Dynamic values that change per test run

## Scrubbing Rules Applied

Following the bd-2pbfa specification, these fields are scrubbed in golden comparisons:

### Database Paths
- `database_path` → `[SCRUBBED_PATH]`
- Any temporary file paths → `[SCRUBBED_PATH]`

### Latencies and Durations
- `*_duration_ms` → `[SCRUBBED_LATENCY]`
- `verification_duration_ms` → `[SCRUBBED_LATENCY]`
- `operation_duration_ms` → `[SCRUBBED_LATENCY]`

### Transaction IDs
- `transaction_id` → `[SCRUBBED_TX_ID]`
- `session_id` → `[SCRUBBED_SESSION_ID]`
- `sequence_number` → `[SCRUBBED_SEQ]`

### Counts (when dynamic)
- Operation counts → `[SCRUBBED_COUNT]`
- Cache sizes → `[SCRUBBED_COUNT]`

## Preserved Fields (Exact Match)

These fields MUST match exactly in conformance tests:

- Domain names and owner module paths
- Safety tier assignments (Tier1/Tier2/Tier3)  
- Durability mode assignments (WalFull/WalNormal/Memory)
- Table names and replay support flags
- Replay strategy specifications
- Gate verdict decisions
- Event codes and message patterns

## Regeneration Instructions

To regenerate these golden files when the bd-1a1j contract changes:

1. **Update canonical_classes()**: Modify the hardcoded data in the conformance test
2. **Extract to JSON**: Run the conformance harness with `UPDATE_GOLDENS=1`
3. **Review changes**: Always run `git diff tests/goldens/frankensqlite/` before committing
4. **Validate contract**: Ensure changes align with updated bd-1a1j contract documentation
5. **Update provenance**: Update this file with new generation date and change summary

## Contract Compliance

These golden files implement conformance testing for these bd-1a1j requirements:

- **Persistence Class Catalog**: All 21 classes with correct tier assignments
- **Tier-Durability Mapping**: Tier1→WalFull, Tier2→WalNormal, Tier3→Memory
- **Replay Support Rules**: Tier1&Tier2 must support replay, Tier3 must not
- **Uniqueness Constraints**: Unique domain names, unique table names
- **Module Ownership**: Clear owner module assignment per class
- **Adapter Behavior**: Initialization events, gate logic, operation patterns

## Last Updated

2026-04-21 - Initial extraction for bd-2pbfa conformance harness implementation