# bd-1nk5: SSRF-Deny Default Policy Template

## Bead: bd-1nk5 | Section: 10.13

## Purpose

Provides a default network guard policy template that blocks SSRF-common
internal destinations (localhost, private CIDRs, link-local, cloud metadata,
tailnet ranges). Explicit allowlist exceptions are permitted only when
accompanied by a policy receipt. Builds on the Network Guard egress layer
(bd-2m2b).

## Invariants

| ID | Statement |
|----|-----------|
| INV-SSRF-DEFAULT-DENY | Default template denies all private/internal CIDRs unless explicitly allowed. |
| INV-SSRF-RECEIPT | Every allowlist exception produces a PolicyReceipt with reason and trace_id. |
| INV-SSRF-CIDR-COMPLETE | Blocked ranges cover 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10, and ::1. |
| INV-SSRF-METADATA | Cloud metadata endpoint 169.254.169.254 is always denied unless receipt-gated. |

## Blocked CIDR Ranges

| Range | Description |
|-------|-------------|
| `127.0.0.0/8` | IPv4 loopback |
| `10.0.0.0/8` | RFC 1918 private class A |
| `172.16.0.0/12` | RFC 1918 private class B |
| `192.168.0.0/16` | RFC 1918 private class C |
| `169.254.0.0/16` | Link-local (includes cloud metadata) |
| `100.64.0.0/10` | Carrier-grade NAT / Tailscale |
| `0.0.0.0/8` | "This" network |
| `::1/128` | IPv6 loopback |

## Types

### SsrfPolicyTemplate
- `blocked_cidrs: Vec<CidrRange>` — parsed CIDR deny list
- `allowlist: Vec<AllowlistEntry>` — explicit exceptions
- `connector_id: String`

### CidrRange
- `network: [u8; 4]` — network address bytes
- `prefix_len: u8` — CIDR prefix length (0-32)

### AllowlistEntry
- `host: String` — hostname or IP
- `port: Option<u16>` — optional port restriction
- `reason: String` — required justification
- `receipt: PolicyReceipt`

### PolicyReceipt
- `receipt_id: String` — unique receipt identifier
- `connector_id: String`
- `host: String`
- `issued_at: String` — ISO 8601 timestamp
- `reason: String`
- `trace_id: String` — correlation ID

## Functions

| Function | Signature | Behaviour |
|----------|-----------|-----------|
| `default_template` | `(connector_id) -> SsrfPolicyTemplate` | Returns template with all standard blocked CIDRs. |
| `is_private_ip` | `(ip: &str) -> bool` | Parses IPv4 and checks against all blocked CIDRs. |
| `check_ssrf` | `(template, host, port, protocol) -> Result<Action, SsrfError>` | Evaluates host; blocks private IPs unless allowlisted. |
| `add_allowlist` | `(template, host, port, reason, trace_id, timestamp) -> PolicyReceipt` | Adds exception, returns receipt. |
| `to_egress_policy` | `(template) -> EgressPolicy` | Converts SSRF template to a standard EgressPolicy for the guard. |

## Error Codes

| Code | Trigger |
|------|---------|
| `SSRF_DENIED` | Request targets a blocked CIDR without allowlist entry. |
| `SSRF_INVALID_IP` | Host cannot be parsed as valid IPv4 address. |
| `SSRF_RECEIPT_MISSING` | Allowlist entry lacks required receipt fields. |
| `SSRF_TEMPLATE_INVALID` | Template has no blocked CIDRs or is otherwise malformed. |

## Audit Event Schema

Each SSRF check emits an audit record:

```json
{
  "connector_id": "string",
  "timestamp": "ISO8601",
  "host": "string",
  "port": 443,
  "action": "allow|deny",
  "cidr_matched": "10.0.0.0/8|null",
  "allowlisted": false,
  "trace_id": "string"
}
```

## Expected Artifacts

| Artifact | Path |
|----------|------|
| Default policy TOML | `config/policies/network_guard_default.toml` |
| Security tests | `tests/security/ssrf_default_deny.rs` |
| SSRF test report | `artifacts/section_10_13/bd-1nk5/ssrf_policy_test_report.json` |
| Verification evidence | `artifacts/section_10_13/bd-1nk5/verification_evidence.json` |
| Verification summary | `artifacts/section_10_13/bd-1nk5/verification_summary.md` |
