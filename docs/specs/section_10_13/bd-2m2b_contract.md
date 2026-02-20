# bd-2m2b: Network Guard Egress Layer

## Section: 10.13 — FCP Deep-Mined Expansion Execution Track

## Decision

All connector egress traffic traverses a network guard that enforces
allow/deny policies at the HTTP and TCP layers. Every decision emits
a structured audit event for observability and incident analysis.

## Dependencies

- bd-1vvs: Strict-plus isolation backend

## Egress Policy

| Field              | Type        | Description                              |
|--------------------|-------------|------------------------------------------|
| `connector_id`     | String      | Connector this policy applies to         |
| `default_action`   | Action      | Default when no rule matches (deny)      |
| `http_rules`       | Vec<Rule>   | HTTP-layer allow/deny rules              |
| `tcp_rules`        | Vec<Rule>   | TCP-layer allow/deny rules               |

### Rule

| Field       | Type    | Description                                |
|-------------|---------|-------------------------------------------|
| `host`      | String  | Target host pattern (exact or wildcard)    |
| `port`      | Option  | Target port (None = any)                   |
| `action`    | Action  | allow or deny                              |
| `protocol`  | Proto   | http or tcp                                |

### Actions

| Action  | Meaning                                    |
|---------|--------------------------------------------|
| `allow` | Traffic permitted, audit logged             |
| `deny`  | Traffic blocked, audit logged with reason   |

## Audit Event

| Field           | Type     | Description                            |
|-----------------|----------|----------------------------------------|
| `connector_id`  | String   | Source connector                       |
| `timestamp`     | String   | ISO-8601                               |
| `protocol`      | Proto    | http or tcp                            |
| `host`          | String   | Target host                            |
| `port`          | u16      | Target port                            |
| `action`        | Action   | allow or deny                          |
| `rule_matched`  | Option   | Which rule matched (None = default)    |
| `trace_id`      | String   | Correlation ID for tracing             |

## Invariants

1. **INV-GUARD-ALL-EGRESS**: All connector egress must traverse the guard.
2. **INV-GUARD-DEFAULT-DENY**: If no rule matches, the default action applies
   (deny unless explicitly set to allow).
3. **INV-GUARD-AUDIT**: Every allow/deny decision emits an audit event.
4. **INV-GUARD-ORDERED**: Rules are evaluated in order; first match wins.

## Error Codes

| Code                    | Meaning                                    |
|-------------------------|--------------------------------------------|
| `GUARD_POLICY_INVALID`  | Policy has contradictory or empty rules     |
| `GUARD_EGRESS_DENIED`   | Egress blocked by policy                    |
| `GUARD_AUDIT_FAILED`    | Audit event emission failed                 |

## Artifacts

- `crates/franken-node/src/security/network_guard.rs` — Network guard impl
- `tests/conformance/network_guard_policy.rs` — Conformance tests
- `fixtures/network_guard/*.json` — Policy test fixtures
- `artifacts/section_10_13/bd-2m2b/network_guard_audit_samples.jsonl` — Audit samples
- `docs/specs/section_10_13/bd-2m2b_contract.md` — This specification
