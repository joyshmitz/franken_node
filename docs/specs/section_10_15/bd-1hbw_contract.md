# bd-1hbw: Control-Plane Epoch Barrier Integration

**Section:** 10.15 | **Type:** task | **Priority:** P1

## Overview

Integrates the canonical epoch transition barrier protocol (bd-2wsm, 10.14)
across control services with explicit abort semantics. Four barrier
participants, deterministic commit/abort, replay-stable transcripts.

## Barrier Participants (4)

- connector_lifecycle, rollout_engine, fencing_service, health_gate

## Invariants

| ID | Rule |
|----|------|
| INV-EPB-CANONICAL | Uses canonical 10.14 barrier protocol |
| INV-EPB-ALL-ARRIVE | All participants must arrive before commit |
| INV-EPB-NO-SPLIT-BRAIN | Abort leaves all in previous epoch |
| INV-EPB-DETERMINISTIC-ABORT | Cancel/timeout abort is deterministic |
| INV-EPB-TRANSCRIPT-STABLE | Barrier transcript is replay-stable |

## Artifacts

- `docs/integration/control_epoch_barrier_adoption.md`
- `artifacts/10.15/control_epoch_barrier_transcript.json`
- `scripts/check_epoch_barrier_adoption.py`
- `tests/test_check_epoch_barrier_adoption.py`
