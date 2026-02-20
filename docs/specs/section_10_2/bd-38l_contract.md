# bd-38l: Divergence Ledger with Signed Rationale Entries

## Decision Rationale

The canonical plan (Section 10.2) requires every behavioral divergence from Node/Bun to be recorded in a structured ledger with signed rationale. This ensures policy-visible compatibility — divergences are never silent, always auditable, and classified by risk.

## Ledger Format

Each divergence entry includes:
- **id**: Unique divergence ID (e.g., `DIV-001`)
- **behavior_id**: Reference to compatibility registry entry
- **api_family**: API family affected
- **api_name**: Specific API
- **band**: Compatibility band (core, high-value, edge, unsafe)
- **node_behavior**: Description of Node.js/Bun behavior
- **franken_behavior**: Description of franken_node behavior
- **rationale**: Signed rationale for the divergence
- **risk_tier**: Risk classification (critical, high, medium, low)
- **status**: Current status (accepted, under-review, deprecated)
- **timestamp**: When the divergence was recorded
- **reviewer**: Who approved the divergence rationale

## Invariants

1. `docs/DIVERGENCE_LEDGER.json` exists and is valid JSON.
2. A JSON schema exists at `schemas/divergence_ledger.schema.json`.
3. Every entry has all required fields.
4. Risk tier, band, and status values are from allowed enums.
5. Each divergence ID is unique.
6. Rationale field is non-empty for every entry.

## Interface Boundaries

- **Input**: `docs/DIVERGENCE_LEDGER.json`
- **Input**: `schemas/divergence_ledger.schema.json`
- **Output**: PASS/FAIL verdict on ledger validity

## Failure Semantics

- Missing ledger or schema: FAIL
- Invalid JSON: FAIL
- Entry missing required fields: FAIL per entry
- Empty rationale: FAIL per entry
- Duplicate IDs: FAIL
