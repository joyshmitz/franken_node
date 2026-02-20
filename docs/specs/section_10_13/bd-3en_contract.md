# bd-3en: Connector Protocol Conformance Harness and Publication Gate

## Section: 10.13 — FCP Deep-Mined Expansion Execution Track

## Decision

A conformance harness runs the full standard method contract validator
against every connector before registry publication. Non-conformant
connectors are blocked from publication. Bypass requires an explicit
policy override artifact signed by an authorized operator.

## Dependencies

- bd-1h6: Standard connector method contract validator

## Harness Architecture

The conformance harness:
1. Discovers all connector packages in the publication pipeline
2. Runs the method contract validator against each connector
3. Aggregates per-connector results into a publication gate report
4. Blocks publication if any required check fails
5. Allows bypass only with a valid policy override artifact

## Publication Gate Logic

```
FOR each connector in publication_queue:
    result = validate_contract(connector)
    IF result.verdict == "FAIL":
        IF has_valid_override(connector):
            log("OVERRIDE: {connector} published despite failures")
        ELSE:
            block_publication(connector)
            log("BLOCKED: {connector} failed conformance")
```

## Policy Override Artifact

```json
{
  "override_id": "OVERRIDE-<timestamp>",
  "connector_id": "<connector>",
  "reason": "<justification>",
  "authorized_by": "<operator>",
  "expires_at": "<ISO 8601>",
  "scope": ["METHOD_MISSING:<method>", ...]
}
```

## Invariants

1. **INV-HARNESS-DETERMINISTIC**: Same connector input always produces the same
   pass/fail result. No flaky or timing-dependent checks.
2. **INV-GATE-FAIL-CLOSED**: Publication is blocked by default on any failure.
   The safe state is "do not publish."
3. **INV-OVERRIDE-EXPLICIT**: Bypass requires a machine-readable override artifact.
   No implicit or silent bypasses exist.
4. **INV-OVERRIDE-SCOPED**: Overrides are scoped to specific failure codes.
   A METHOD_MISSING override does not bypass SCHEMA_MISMATCH.
5. **INV-OVERRIDE-EXPIRY**: Overrides carry an expiration timestamp. Expired
   overrides are treated as absent.

## Error Codes

| Code                     | Meaning                                        |
|--------------------------|------------------------------------------------|
| `PUBLICATION_BLOCKED`    | Connector failed conformance, no valid override |
| `OVERRIDE_EXPIRED`       | Override artifact has passed its expiry date     |
| `OVERRIDE_SCOPE_MISMATCH`| Override does not cover the specific failure     |

## Artifacts

- `tests/conformance/connector_protocol_harness.rs` — Harness implementation
- `.github/workflows/connector-conformance.yml` — CI workflow
- `artifacts/section_10_13/bd-3en/publication_gate_evidence.json` — Evidence
- `artifacts/section_10_13/bd-3en/verification_evidence.json` — Gate evidence
- `artifacts/section_10_13/bd-3en/verification_summary.md` — Human summary
