# Intent-Aware Remote Effects Firewall Policy (bd-3l2p)

## Scope

This contract governs the intent-aware remote effects firewall for
extension-originated traffic in `franken_node`. Every outbound remote effect
from an extension is classified by intent category, matched against traffic
policy rules, and issued a deterministic decision receipt. Risky intent
categories default to deny/quarantine pathways. Unclassifiable traffic is
denied (fail-closed).

## Core Invariants

- `INV-FIREWALL-STABLE-CLASSIFICATION`: identical effect descriptors always
  produce the same intent classification.
- `INV-FIREWALL-DETERMINISTIC-RECEIPT`: identical inputs (effect, trace_id,
  timestamp) produce identical decision receipts.
- `INV-FIREWALL-FAIL-DENY`: any traffic that cannot be classified is denied.
- `INV-FIREWALL-RISKY-PATHWAY`: risky intent categories (exfiltration,
  credential forwarding, side-channel probing) trigger
  challenge/simulate/deny/quarantine pathways.

## Internal Invariants

- `INV-FW-FAIL-CLOSED`: unclassifiable traffic is denied.
- `INV-FW-RECEIPT-EVERY-DECISION`: every firewall decision produces a receipt.
- `INV-FW-RISKY-DEFAULT-DENY`: risky categories default to deny/quarantine.
- `INV-FW-DETERMINISTIC`: identical inputs produce identical outputs.
- `INV-FW-EXTENSION-SCOPED`: firewall applies only to extension traffic.

## Intent Classification Categories

| Category | Risky | Default Verdict |
|---|---|---|
| DataFetch | No | Allow |
| DataMutation | No | Allow |
| WebhookDispatch | No | Allow |
| AnalyticsExport | No | Allow |
| Exfiltration | Yes | Deny |
| CredentialForward | Yes | Deny |
| SideChannel | Yes | Deny |
| ServiceDiscovery | No | Allow |
| HealthCheck | No | Allow |
| ConfigSync | No | Allow |

## Classification Rules

1. If the request carries credentials, classify as `CredentialForward`.
2. If the payload contains sensitive data markers, classify as `Exfiltration`.
3. If `probe_mode` metadata is set, classify as `SideChannel`.
4. Path heuristics: `/health`, `/config`, `/webhook`, `/analytics`,
   `/discover`, `/services`.
5. HTTP method: POST/PUT/PATCH/DELETE -> `DataMutation`,
   GET/HEAD/OPTIONS -> `DataFetch`.
6. If none of the above match, the request is unclassifiable and denied.

## Verdict Pathways

- **Allow**: traffic proceeds normally.
- **Challenge**: traffic requires interactive challenge before proceeding.
- **Simulate**: traffic is sandboxed for simulated evaluation.
- **Deny**: traffic is rejected.
- **Quarantine**: traffic is held for later review (capacity-bounded).

## Decision Receipt Schema

Every decision produces a `FirewallDecision` receipt containing:

- `receipt_id`
- `trace_id`
- `effect_id`
- `origin`
- `intent` (optional, None if unclassifiable)
- `verdict`
- `event_code`
- `matched_rule_priority`
- `rationale`
- `timestamp`
- `schema_version`

## Event Codes

- `FIREWALL_REQUEST_CLASSIFIED`: request has been classified by intent.
- `FIREWALL_INTENT_BENIGN`: classified intent is non-risky.
- `FIREWALL_INTENT_RISKY`: classified intent is risky.
- `FIREWALL_CHALLENGE_ISSUED`: challenge pathway triggered.
- `FIREWALL_VERDICT_RENDERED`: final verdict produced with receipt.
- `FW_001` through `FW_010`: internal operational event codes.

## Error Codes

- `ERR_FIREWALL_CLASSIFICATION_FAILED`: intent classification could not complete.
- `ERR_FIREWALL_CHALLENGE_TIMEOUT`: challenge pathway timed out.
- `ERR_FIREWALL_SIMULATE_FAILED`: simulation sandbox execution failed.
- `ERR_FIREWALL_QUARANTINE_FULL`: quarantine capacity exhausted.
- `ERR_FIREWALL_RECEIPT_UNSIGNED`: decision receipt lacks required signature.
- `ERR_FIREWALL_POLICY_MISSING`: no traffic policy loaded for evaluation.
- `ERR_FW_UNCLASSIFIED`, `ERR_FW_NO_POLICY`, `ERR_FW_INVALID_EFFECT`,
  `ERR_FW_RECEIPT_FAILED`, `ERR_FW_POLICY_CONFLICT`,
  `ERR_FW_EXTENSION_UNKNOWN`, `ERR_FW_OVERRIDE_UNAUTHORIZED`,
  `ERR_FW_QUARANTINE_FULL`: internal error codes.

## Policy Override

An operator may add a `PolicyOverride` for a specific extension and intent
category. The override must include a non-empty justification and approved_by
field. Overrides without justification are rejected with
`ERR_FW_OVERRIDE_UNAUTHORIZED`.

## Required Artifacts

- `crates/franken-node/src/security/intent_firewall.rs`
- `tests/security/intent_firewall_conformance.rs`
- `artifacts/10.17/intent_firewall_eval_report.json`
- `artifacts/section_10_17/bd-3l2p/verification_evidence.json`
- `artifacts/section_10_17/bd-3l2p/verification_summary.md`
