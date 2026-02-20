# bd-1h6: Standard Connector Method Contract Validator

## Section: 10.13 — FCP Deep-Mined Expansion Execution Track

## Decision

Every connector must implement a standard set of nine methods. A contract
validator checks that all required methods exist, conform to their pinned
schemas, and produce deterministic responses. Connectors that fail validation
are rejected from the registry.

## Dependencies

- bd-1rk: Health gating and rollout-state persistence (provides lifecycle context)

## Standard Methods

| Method          | Required | Direction    | Purpose                                    |
|-----------------|----------|--------------|--------------------------------------------|
| `handshake`     | yes      | bidirectional| Protocol version negotiation                |
| `describe`      | yes      | connector→host| Self-description (name, version, author)   |
| `introspect`    | yes      | connector→host| Runtime capability and state report         |
| `capabilities`  | yes      | connector→host| Declared capability set                     |
| `configure`     | yes      | host→connector| Apply configuration                        |
| `simulate`      | no       | host→connector| Dry-run invocation without side effects     |
| `invoke`        | yes      | host→connector| Execute the connector's primary function    |
| `health`        | yes      | host→connector| Health check (liveness + readiness)          |
| `shutdown`      | yes      | host→connector| Graceful shutdown                           |

## Method Schema Structure

Each method schema is defined by:

```
{
  "method": "<method_name>",
  "version": "<semver>",
  "required": true|false,
  "input_schema": { ... },
  "output_schema": { ... }
}
```

## Invariants

1. **INV-METHOD-COMPLETE**: All 8 required methods must be present. Missing
   required methods cause validation failure.
2. **INV-METHOD-SCHEMA**: Each method's input and output must conform to its
   pinned schema version. Schema mismatches cause validation failure.
3. **INV-METHOD-VERSIONED**: Method schemas carry a semver version. The validator
   checks that the connector's schema version is compatible with the pinned version.
4. **INV-METHOD-REPORT**: Validation produces a machine-readable JSON report with
   per-method pass/fail status, schema version, and error details.

## Error Codes

| Code                  | Meaning                                      |
|-----------------------|----------------------------------------------|
| `METHOD_MISSING`      | A required method is not implemented          |
| `SCHEMA_MISMATCH`     | Method schema does not match pinned version   |
| `VERSION_INCOMPATIBLE`| Method schema version is not compatible       |
| `RESPONSE_INVALID`    | Method response does not match output schema  |

## Artifacts

- `crates/franken-node/src/conformance/connector_method_validator.rs` — Validator
- `docs/specs/section_10_13/bd-1h6_contract.md` — This specification
- `artifacts/section_10_13/bd-1h6/connector_method_contract_report.json` — Report
- `artifacts/section_10_13/bd-1h6/verification_evidence.json` — Gate evidence
- `artifacts/section_10_13/bd-1h6/verification_summary.md` — Human summary
