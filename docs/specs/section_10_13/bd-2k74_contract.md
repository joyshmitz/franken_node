# bd-2k74: Per-Peer Admission Budgets

## Purpose

Enforce multi-dimensional per-peer admission budgets: bytes, symbols, failed-auth, inflight-decode, and decode-cpu. Limit breaches are rate-limited and logged. Budgets are configurable without code changes.

## Invariants

- **INV-PAB-ENFORCED**: Every admission check evaluates all budget dimensions; no dimension is silently skipped.
- **INV-PAB-BOUNDED**: A peer that exceeds any budget dimension is rejected before processing continues.
- **INV-PAB-AUDITABLE**: Every budget check emits a structured record with peer_id, dimension, usage, limit, and verdict.
- **INV-PAB-DETERMINISTIC**: Same peer state + same config → same admit/reject decision.

## Types

### AdmissionBudget

Per-peer budget limits: max_bytes, max_symbols, max_failed_auth, max_inflight_decode, max_decode_cpu_ms.

### PeerUsage

Current usage counters per peer: bytes_used, symbols_used, failed_auth_count, inflight_decode_count, decode_cpu_ms.

### AdmissionRequest

Incoming request for admission: peer_id, bytes_requested, symbols_requested, decode_cpu_estimate_ms.

### AdmissionVerdict

Result: peer_id, admitted (bool), violated_dimensions, remaining budgets, trace_id.

### BudgetCheckRecord

Audit record: peer_id, timestamp, dimension checked, usage_before, requested, limit, verdict.

## Error Codes

- `PAB_BYTES_EXCEEDED` — peer exceeded bytes budget
- `PAB_SYMBOLS_EXCEEDED` — peer exceeded symbols budget
- `PAB_AUTH_EXCEEDED` — peer exceeded failed-auth budget
- `PAB_INFLIGHT_EXCEEDED` — peer exceeded inflight-decode budget
- `PAB_CPU_EXCEEDED` — peer exceeded decode-cpu budget
- `PAB_INVALID_BUDGET` — budget configuration is invalid
