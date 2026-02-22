# Optimization Governor Spec

**Bead:** bd-21fo  
**Section:** 10.17

## Intent

The optimization governor adapts exposed runtime knobs while enforcing a hard
safety envelope. Every proposal is shadow-evaluated before apply, and every
reject/revert emits deterministic machine-readable evidence.

## Safety Envelope

- `max_latency_ms`: hard p99 latency cap
- `min_throughput_rps`: floor for throughput
- `max_error_rate_pct`: error ceiling in `[0.0, 100.0]`
- `max_memory_mb`: memory ceiling

## Exposed Knobs

- `concurrency_limit`
- `batch_size`
- `cache_capacity`
- `drain_timeout_ms`
- `retry_budget`

No engine-core internals are mutable by the governor.

## Decision Flow

1. Proposal submission (`GOV_001`)
2. Shadow evaluation start (`GOV_002`)
3. Approve and apply (`GOV_003`) or reject (`GOV_004`)
4. Anytime-valid live enforcement, with auto-revert on breach (`GOV_005`)
5. Envelope updates (`GOV_006`) and snapshots (`GOV_007`)

## Error Codes

- `ERR_GOV_ENVELOPE_VIOLATION`
- `ERR_GOV_NON_BENEFICIAL`
- `ERR_GOV_KNOB_LOCKED`
- `ERR_GOV_REVERT_FAILED`
- `ERR_GOV_SHADOW_TIMEOUT`
- `ERR_GOV_INVALID_PROPOSAL`

## Invariants

- `INV-GOV-ENVELOPE-NEVER-BREACHED`
- `INV-GOV-SHADOW-BEFORE-APPLY`
- `INV-GOV-EVIDENCE-ON-REJECT`
- `INV-GOV-KNOBS-ONLY`
- `INV-GOV-AUTO-REVERT`
- `INV-GOV-DETERMINISTIC-ORDER`
