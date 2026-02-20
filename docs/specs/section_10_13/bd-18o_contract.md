# bd-18o: Canonical Connector State Root/Object Model

## Section: 10.13 — FCP Deep-Mined Expansion Execution Track

## Decision

Every connector must declare its state model type. A canonical state root
object is persisted for each connector, acting as the single source of truth.
Local cache divergence from the canonical root is detectable and repairable
through a reconciliation protocol.

## Dependencies

- bd-3en: Conformance harness (provides publication gate context)

## State Model Types

| Type           | Description                                        |
|----------------|----------------------------------------------------|
| `stateless`    | Connector holds no persistent state                |
| `key_value`    | State is a set of key-value pairs                  |
| `document`     | State is a structured JSON document                |
| `append_only`  | State grows monotonically (log/event stream)       |

## State Root Object

```rust
pub struct StateRoot {
    pub connector_id: String,
    pub state_model: StateModelType,
    pub root_hash: String,         // SHA-256 of canonical state
    pub version: u64,              // monotonic version counter
    pub last_modified: String,     // ISO 8601
    pub head: serde_json::Value,   // the actual state data
}
```

## Cache Divergence Detection

The local cache stores a copy of the state root. Divergence occurs when:
1. `root_hash` differs between local and canonical
2. `version` in local is behind canonical (stale)
3. `version` in local is ahead of canonical (split-brain)

## Reconciliation

| Divergence Type | Action                                |
|-----------------|---------------------------------------|
| stale           | Pull canonical root and replace local |
| split-brain     | Flag for operator review              |
| hash mismatch   | Re-derive hash, repair if needed      |

## Invariants

1. **INV-STATE-TAGGED**: Every connector must declare a `StateModelType`. Connectors
   without a declared type are rejected.
2. **INV-ROOT-CANONICAL**: The persisted state root is the single source of truth.
   Local caches are derived copies.
3. **INV-ROOT-HASHED**: The root hash is a SHA-256 digest of the serialized head.
   Hash mismatches indicate corruption or tampering.
4. **INV-DIVERGENCE-DETECTABLE**: Comparing local and canonical root_hash + version
   deterministically identifies all divergence types.

## Error Codes

| Code                  | Meaning                                      |
|-----------------------|----------------------------------------------|
| `STATE_MODEL_MISSING` | Connector has no declared state model type   |
| `ROOT_HASH_MISMATCH`  | Computed hash differs from stored hash       |
| `CACHE_STALE`         | Local version behind canonical version       |
| `CACHE_SPLIT_BRAIN`   | Local version ahead of canonical (conflict)  |

## Artifacts

- `crates/franken-node/src/connector/state_model.rs` — State model implementation
- `tests/integration/connector_state_persistence.rs` — Integration tests
- `artifacts/section_10_13/bd-18o/state_model_samples.json` — Sample states
- `artifacts/section_10_13/bd-18o/verification_evidence.json` — Gate evidence
- `artifacts/section_10_13/bd-18o/verification_summary.md` — Human summary
