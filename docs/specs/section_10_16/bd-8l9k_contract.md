# bd-8l9k: Cross-Substrate Contract Tests — End-to-End Behavior Validation

**Section:** 10.16 — Adjacent Substrate Integration
**Type:** E2E Contract Tests
**Status:** Delivered
**Schema:** gate-v1.0

## Purpose

Add cross-substrate contract tests that validate end-to-end flows across all four
substrate planes: frankentui (presentation), fastapi_rust (service), sqlmodel_rust
(model), and frankensqlite (persistence). These tests verify correct behavior for
operator status, lease management, audit logging, error propagation, and concurrent
access. They also validate W3C Trace Context propagation, replay determinism, and
error fidelity across substrate boundaries.

## Data Model

| Type | Kind | Description |
|------|------|-------------|
| `Substrate` | enum | Four adjacent substrate variants: FrankenTui, FastapiRust, SqlmodelRust, FrankenSqlite |
| `TraceContext` | struct | W3C Trace Context with trace_id, span_id, parent_span_id, substrate, operation |
| `TraceTree` | struct | Collected spans forming a trace tree; detects orphaned spans |
| `FencingToken` | struct | Epoch-based fencing token for lease concurrency control |
| `AuditLogEntry` | struct | Hash-chained audit entry with substrate, operation, operator_id |
| `AuditLog` | struct | Verifiable audit log with hash-chain integrity |
| `StructuredError` | struct | Cross-substrate error with code, message, substrate, trace_id, details (BTreeMap) |
| `ReplaySeed` | struct | Deterministic seed + mock clock start for replay |
| `ReplayResult` | struct | Replay output hash + event sequence for determinism verification |
| `MockClock` | struct | Deterministic mock clock (Arc<Mutex<u64>>) for E2E tests |
| `MockPersistence` | struct | In-memory persistence with fencing token enforcement (BTreeMap) |
| `MockService` | struct | Service layer mock with persistence + audit log |
| `MockTui` | struct | TUI layer mock with panel rendering + error display |
| `ScenarioOutcome` | enum | Pass or Fail(String) |
| `ScenarioResult` | struct | E2E scenario result with trace, events, duration |
| `ScenarioRunner` | struct | Collects scenario results and produces BTreeMap summary |

## Invariants

- **INV-E2E-TRACE**: Every span must have a valid parent or be root. No orphaned spans.
- **INV-E2E-REPLAY**: Identical seeds + mock clocks produce byte-identical replay results.
- **INV-E2E-FENCING**: Stale fencing tokens are always rejected; writes are serialized.
- **INV-E2E-AUDIT**: Every state-mutating operation produces a hash-chained audit entry.
- **INV-E2E-ERROR-FIDELITY**: Errors preserve structured code and context across substrates.
- **INV-E2E-SCHEMA-COMPAT**: All cross-substrate messages conform to e2e-v1.0.
- **INV-E2E-CONCURRENT-SAFETY**: Concurrent access does not produce torn reads or lost updates.

## Event Codes

| Code | Description |
|------|-------------|
| `E2E_SCENARIO_START` | E2E scenario begins execution |
| `E2E_SCENARIO_PASS` | E2E scenario passes all assertions |
| `E2E_SCENARIO_FAIL` | E2E scenario fails one or more assertions |
| `E2E_TRACE_ORPHAN_DETECTED` | Orphaned span detected in trace tree |
| `E2E_REPLAY_MISMATCH` | Replay produces different result than original |
| `E2E_CONCURRENT_CONFLICT` | Concurrent operator fencing conflict |

## Error Codes

| Code | Description |
|------|-------------|
| `ERR_E2E_SETUP_FAILED` | Scenario setup failure |
| `ERR_E2E_TRACE_BROKEN` | Trace context propagation failure |
| `ERR_E2E_REPLAY_DIVERGED` | Replay determinism assertion failure |
| `ERR_E2E_PERSISTENCE_MISMATCH` | Persistence layer unexpected data |
| `ERR_E2E_SERVICE_ERROR` | Service layer unstructured error |
| `ERR_E2E_CONCURRENT_INCONSISTENT` | Concurrent access inconsistent state |
| `ERR_E2E_TUI_RENDER_FAILED` | TUI render layer invalid data |
| `ERR_E2E_AUDIT_MISSING` | Audit log entry missing or malformed |
| `ERR_E2E_FENCING_REJECTED` | Fencing token stale or rejected |
| `ERR_E2E_SCHEMA_MISMATCH` | Schema version mismatch |

## E2E Scenarios

1. **Operator Status Flow** — TUI initiates status update -> service processes -> persistence stores -> TUI renders result
2. **Lease Management Flow** — TUI requests lease -> service validates fencing token -> persistence stores -> TUI confirms
3. **Audit Log Flow** — Actions generate audit entries -> service records -> persistence stores hash chain -> verifier checks -> TUI renders
4. **Error Propagation Flow** — Invalid request (stale token) -> structured error with code -> TUI renders error panel -> audit records
5. **Concurrent Access Flow** — Two operators contend for same resource -> fencing serializes -> stale operator rejected -> consistency verified
6. **Trace Propagation** — W3C trace context propagated across all four substrates with no orphaned spans
7. **Replay Determinism** — Same scenario replayed with identical seed/clock produces identical output hash and event sequence

## Acceptance Criteria

- [ ] 7 E2E scenarios covering all four substrate planes
- [ ] All scenarios pass with deterministic seeds and mock clocks
- [ ] No orphaned spans in any trace tree
- [ ] Replay produces byte-identical results
- [ ] Fencing tokens reject stale writes
- [ ] Audit log hash chain verifies
- [ ] Structured errors preserve code and context across substrates
- [ ] 45+ Rust unit tests
- [ ] BTreeMap used for deterministic ordering
- [ ] Schema version "e2e-v1.0" declared
- [ ] All event codes and error codes defined as constants

## Artifacts

- E2E test module: `tests/e2e/adjacent_substrate_flow.rs`
- E2E module wiring: `tests/e2e/mod.rs`
- E2E report: `artifacts/10.16/adjacent_substrate_e2e_report.json`
- Spec contract: `docs/specs/section_10_16/bd-8l9k_contract.md`
- Gate script: `scripts/check_cross_substrate_e2e.py`
- Python tests: `tests/test_check_cross_substrate_e2e.py`
- Evidence: `artifacts/section_10_16/bd-8l9k/verification_evidence.json`
- Summary: `artifacts/section_10_16/bd-8l9k/verification_summary.md`

## Dependencies

- Section 10.16 adjacent substrate integration beads
- Downstream: section gate bd-10g0
