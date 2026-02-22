# bd-2qqu: Virtual Transport Fault Harness

**Section:** 10.14 -- Remote Capabilities & Protocol Testing
**Bead:** bd-2qqu
**Status:** IN_PROGRESS

## Purpose

Provide a deterministic, seed-driven virtual transport fault harness that injects
controlled faults (drop, reorder, corrupt) into a simulated transport layer.
The harness enables systematic protocol testing by generating reproducible fault
schedules from a seed, executing campaigns against pre-built or custom scenarios,
and producing structured audit trails for post-hoc analysis.

## Dependencies

- **Upstream:** none (standalone harness with no external module dependencies)

## Types

### `FaultClass`

Enum representing the three fault injection classes:

- `Drop` -- message is silently discarded
- `Reorder { depth: usize }` -- message delivery is delayed by `depth` slots via
  a reorder buffer
- `Corrupt { bit_positions: Vec<usize> }` -- specific bits in the payload are
  flipped (XOR with 1)

Derives: `Debug, Clone, PartialEq, Eq, Serialize, Deserialize`.
Implements `Display`.

### `FaultConfig`

Configuration struct controlling fault injection probabilities and limits:

- `drop_probability: f64` -- probability of a drop fault per message (range [0, 1])
- `reorder_probability: f64` -- probability of a reorder fault per message (range [0, 1])
- `reorder_max_depth: usize` -- maximum reorder buffer depth
- `corrupt_probability: f64` -- probability of a corrupt fault per message (range [0, 1])
- `corrupt_bit_count: usize` -- number of bits to flip per corruption event
- `max_faults: usize` -- global fault budget (must be > 0)

`validate()` returns `Err(String)` if any probability is outside [0, 1] or
`max_faults` is 0.

### `ScheduledFault`

A fault action bound to a specific message index:

- `message_index: usize`
- `fault: FaultClass`

### `FaultSchedule`

A deterministic fault schedule generated from a seed:

- `seed: u64`
- `faults: Vec<ScheduledFault>`
- `total_messages: usize`

### `FaultEvent`

A single recorded fault event in the fault log:

- `fault_id: u64` -- monotonically increasing
- `fault_class: String`
- `message_id: u64`
- `details: serde_json::Value`

### `CampaignResult`

Summary of a completed campaign run:

- `scenario_name: String`
- `seed: u64`
- `total_messages: usize`
- `total_faults: usize`
- `drops: usize`
- `reorders: usize`
- `corruptions: usize`
- `content_hash: String` -- SHA-256 hash of the serialized fault schedule

### `VtfAuditRecord`

Audit log entry for harness operations:

- `event_code: String`
- `trace_id: String`
- `detail: serde_json::Value`

### `VirtualTransportFaultHarness`

The core harness managing fault injection, logging, and audit:

- `seed: u64`
- `fault_log: Vec<FaultEvent>`
- `reorder_buffer: VecDeque<(u64, Vec<u8>)>`
- `next_fault_id: u64`
- `audit_log: Vec<VtfAuditRecord>`

## Operations

### `VirtualTransportFaultHarness::new(seed: u64) -> Self`

Create a new harness with the given seed. No audit entry emitted.

### `VirtualTransportFaultHarness::init(seed: u64, trace_id: &str) -> Self`

Create a new harness and emit a `FAULT_HARNESS_INIT` audit entry.

### `apply_drop(message_id, payload, trace_id) -> Option<Vec<u8>>`

Drop the message. Returns `None`. Records a fault event and emits
`FAULT_DROP_APPLIED` audit entry.

### `apply_reorder(message_id, payload, depth, trace_id) -> Option<Vec<u8>>`

Buffer the message for delayed delivery. Returns a previously buffered message
if the buffer exceeds `depth`, otherwise `None`. Records a fault event and emits
`FAULT_REORDER_APPLIED` audit entry.

### `apply_corrupt(message_id, payload, bit_positions, trace_id) -> Vec<u8>`

Flip the specified bits in the payload (byte_idx = bit_pos / 8, bit_idx = bit_pos % 8).
Returns the corrupted payload. Records a fault event and emits
`FAULT_CORRUPT_APPLIED` audit entry.

### `process_message(schedule, msg_idx, message_id, payload, trace_id) -> Option<Vec<u8>>`

Route a message through the fault schedule. If `msg_idx` matches a scheduled
fault, apply it. Otherwise pass through with `FAULT_NONE` audit entry.

### `run_campaign(scenario_name, config, total_messages, trace_id) -> CampaignResult`

Generate a fault schedule from the harness seed and config, compute summary
statistics, SHA-256 content hash, and emit `FAULT_SCENARIO_START` and
`FAULT_CAMPAIGN_COMPLETE` audit entries.

### `flush_reorder_buffer() -> Vec<Vec<u8>>`

Drain all remaining messages from the reorder buffer.

### `export_fault_log_jsonl() -> String`

Serialize the fault log as newline-delimited JSON.

### `export_audit_log_jsonl() -> String`

Serialize the audit log as newline-delimited JSON.

### `fault_count() -> usize`

Return the number of recorded fault events.

### `FaultSchedule::from_seed(seed, config, total_messages) -> FaultSchedule`

Generate a deterministic fault schedule using xorshift64 PRNG. For each message
index, the PRNG state advances and a roll determines which (if any) fault is
scheduled: drop, reorder, or corrupt, based on cumulative probability thresholds.

## Pre-built Scenarios

| Function | Drop % | Reorder % | Depth | Corrupt % | Bits | Budget |
|----------|--------|-----------|-------|-----------|------|--------|
| `no_faults()` | 0 | 0 | 0 | 0 | 0 | 1000 |
| `moderate_drops()` | 5 | 0 | 0 | 0 | 0 | 1000 |
| `heavy_reorder()` | 0 | 20 | 5 | 0 | 0 | 1000 |
| `light_corruption()` | 0 | 0 | 0 | 1 | 1 | 1000 |
| `chaos()` | 15 | 15 | 5 | 10 | 2 | 5000 |

## Invariants

| ID | Description |
|----|-------------|
| INV-VTF-DETERMINISTIC | Same seed + config + message count always produces identical fault schedule |
| INV-VTF-DROP | Drop faults return None and increment fault count |
| INV-VTF-REORDER | Reorder faults buffer messages and respect depth limit |
| INV-VTF-CORRUPT | Corrupt faults flip exactly the specified bits |
| INV-VTF-LOGGED | Every fault action is recorded in both fault log and audit log |
| INV-VTF-REPRODUCIBLE | Campaign content hash is deterministic for same seed |

## Event Codes

| Code | Emitted By |
|------|------------|
| `FAULT_INJECTED` | Generic fault injection marker |
| `FAULT_SCHEDULE_CREATED` | Schedule generation |
| `FAULT_CAMPAIGN_COMPLETE` | Campaign runner completion |
| `FAULT_LOG_EXPORTED` | Log export operations |
| `FAULT_DROP_APPLIED` | `apply_drop()` |
| `FAULT_REORDER_APPLIED` | `apply_reorder()` |
| `FAULT_CORRUPT_APPLIED` | `apply_corrupt()` |
| `FAULT_NONE` | `process_message()` passthrough |
| `FAULT_HARNESS_INIT` | `init()` constructor |
| `FAULT_SCENARIO_START` | `run_campaign()` start |
| `FAULT_SCENARIO_END` | Campaign scenario boundary |
| `FAULT_AUDIT_EMITTED` | Audit record written |

## Edge Cases

- Reorder with `depth=0` or `max_depth=0`: buffer never exceeds depth, messages returned immediately or never
- Corrupt with bit positions beyond payload length: out-of-bounds positions silently skipped
- `no_faults()` scenario: schedule contains zero faults regardless of seed
- `max_faults` budget exhausted: remaining messages pass through unfaulted
- Empty payload corruption: no bits flipped if payload is empty

## Performance Targets

- `FaultSchedule::from_seed`: O(n) in message count, < 1ms for 10,000 messages
- `apply_drop`: O(1)
- `apply_reorder`: O(1) amortized
- `apply_corrupt`: O(k) where k = number of bit positions
- `export_fault_log_jsonl`: O(n) in fault count

## Artifacts

- Implementation: `crates/franken-node/src/remote/virtual_transport_faults.rs`
- Spec: `docs/specs/section_10_14/bd-2qqu_contract.md`
- Verification script: `scripts/check_virtual_transport_faults.py`
- Unit tests: `tests/test_check_virtual_transport_faults.py`
- Evidence: `artifacts/section_10_14/bd-2qqu/verification_evidence.json`
- Summary: `artifacts/section_10_14/bd-2qqu/verification_summary.md`
