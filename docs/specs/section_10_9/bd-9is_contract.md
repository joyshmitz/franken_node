# bd-9is: Autonomous Adversarial Campaign Runner

**Section**: 10.9 — Moonshot Disruption Track
**Type**: Security testing infrastructure
**Status**: Active

## Purpose

Provide an autonomous adversarial campaign runner that continuously generates,
evolves, and evaluates attack campaigns against franken_node's trust and
security infrastructure. Ensures defense posture is tested against both known
attack patterns and novel combinations, with results feeding back into the
adversary graph and trust card systems.

## Campaign Categories

| Category ID | Description |
|---|---|
| `CAMP-MEI` | Malicious extension injection (native code, restricted APIs, privilege escalation) |
| `CAMP-CEX` | Credential exfiltration (env vars, filesystem, network, memory) |
| `CAMP-PEV` | Policy evasion (timing, TOCTOU, interpretation ambiguity) |
| `CAMP-DPA` | Delayed payload activation (dormant triggers, behavioral phase shifts) |
| `CAMP-SCC` | Supply-chain compromise (dependency substitution, typosquatting, pinning attacks) |

## Mutation Strategies

| Strategy ID | Description |
|---|---|
| `MUT-PARAM` | Parameter variation — modify attack parameters (timing, payload size, target scope) |
| `MUT-COMBO` | Technique combination — compose multiple attack vectors into a single campaign |
| `MUT-TIMING` | Timing variation — alter attack sequencing, delays, and burst patterns |
| `MUT-EVASION` | Evasion refinement — adapt techniques to bypass specific detected defenses |

## Event Codes

| Code | Description |
|---|---|
| `ADV-RUN-001` | Campaign execution started |
| `ADV-RUN-002` | Campaign execution completed — defense held |
| `ADV-RUN-003` | Campaign execution completed — defense breach detected |
| `ADV-RUN-004` | Campaign mutation applied |
| `ADV-RUN-005` | Campaign corpus updated |
| `ADV-RUN-006` | Result integrated with adversary graph |
| `ADV-RUN-ERR-001` | Campaign execution infrastructure failure |
| `ADV-RUN-ERR-002` | Sandbox containment check failed |

## Invariants

- **INV-ACR-CORPUS**: Campaign corpus is versioned and contains >= 5 categories.
- **INV-ACR-SANDBOX**: All campaigns execute in isolated environments with verified containment.
- **INV-ACR-MUTATION**: At least 3 mutation strategies are implemented and auditable.
- **INV-ACR-RESULTS**: Results are structured JSON with full execution traces.
- **INV-ACR-INTEGRATION**: Results feed into adversary graph and trust card formats.
- **INV-ACR-CONTINUOUS**: Runner supports both continuous and on-demand execution modes.
- **INV-ACR-PROVENANCE**: Every mutation has logged provenance chain.

## Campaign Definition Schema

```json
{
  "campaign_id": "CAMP-MEI-001",
  "category": "CAMP-MEI",
  "version": "1.0.0",
  "title": "Native code loading via disguised extension",
  "attack_vector": "Load a .node addon from an extension claiming pure-JS",
  "target_component": "extension_host",
  "expected_defense": "sandbox blocks native code loading; trust card rejects",
  "severity": "critical",
  "success_criteria": {
    "defense_held": true,
    "detection_time_ms": 100,
    "audit_event_emitted": true
  },
  "payload": { ... },
  "mutations_applied": [],
  "parent_campaign_id": null,
  "created_at": "2026-02-21T00:00:00Z"
}
```

## Result Schema

```json
{
  "campaign_id": "CAMP-MEI-001",
  "execution_id": "exec-uuid",
  "timestamp": "2026-02-21T00:00:00Z",
  "verdict": "defense_held",
  "defense_decisions": [...],
  "execution_trace": [...],
  "sandbox_verified": true,
  "duration_ms": 150,
  "severity_if_breached": "critical",
  "integration_targets": ["adversary_graph", "trust_card"]
}
```

## Artifacts

- `crates/franken-node/src/security/adversarial_runner.rs` — core runner
- `fixtures/campaigns/*.json` — initial corpus
- `scripts/check_adversarial_runner.py` — verification
- `tests/test_check_adversarial_runner.py` — unit tests
