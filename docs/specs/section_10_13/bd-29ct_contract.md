# bd-29ct — Adversarial Fuzz Corpus Gates

## Overview

Builds adversarial fuzz corpus gates covering four target categories: parser
input, handshake replay/splice, token validation, and decode-DoS.  A fuzz
campaign runner executes seeds against targets, triages crashes into
reproducible fixtures, and enforces a minimum health budget (no regressions
from known seeds).

The current implementation intentionally exposes two different surfaces:

- `DeterministicFuzzTestAdapter::run_fixture_gate()` for synthetic fixture and
  modeling coverage only
- `run_truthful_fuzz_gate(...)` for checked-in empirical target execution and
  explicit coverage/artifact reporting

## Fuzz Targets

| Target | Category | Description |
|--------|----------|-------------|
| parser_input | decode-DoS | Malformed/oversized frames |
| handshake_replay | replay/splice | Replayed or spliced handshake sequences |
| token_validation | auth | Malformed/expired/revoked tokens |
| decode_dos | resource exhaustion | CPU/memory exhaustion via crafted payloads |

## Invariants

- **INV-FCG-TARGETS** — Fuzz targets exist for all four categories (parser,
  handshake, token, decode-DoS).
- **INV-FCG-CORPUS** — Each target has a seed corpus of at least 3 inputs;
  seeds cover both valid and adversarial cases.
- **INV-FCG-TRIAGE** — Crashes and hangs are triaged into reproducible fixtures
  with the triggering input, target, and error details.
- **INV-FCG-GATE** — The CI gate checks that all known seeds run without
  regression; any new crash fails the gate with a reproducer.
- **INV-FCG-FIXTURE-BOUNDARY** — Deterministic fixture execution is exposed only
  through a named synthetic adapter and carries explicit synthetic markers.

## Types

- `DeterministicFuzzTestAdapter` — named synthetic fixture adapter for tests
  and modeling
- `DeterministicFuzzTarget` — fixture target name, category, description
- `DeterministicFuzzSeed` — fixture target, input data, expected outcome
- `DeterministicFuzzGateReport` — synthetic adapter report with
  `adapter_kind`, `execution_mode`, and `runner_detail`
- `DeterministicTriagedCrash` — fixture target, seed, synthetic error,
  reproducer
- `TruthfulFuzzGateReport` — live empirical report with target summaries,
  coverage observations, and artifact references
- `FuzzError` — error codes

## Error Codes

| Code | Meaning |
|------|---------|
| `FCG_MISSING_TARGET` | Required fuzz target not found |
| `FCG_INSUFFICIENT_CORPUS` | Target has too few seed inputs |
| `FCG_REGRESSION` | Known seed caused a crash that didn't exist before |
| `FCG_UNTRIAGED_CRASH` | Crash without reproducer fixture |
| `FCG_GATE_FAILED` | Overall fuzz gate did not pass |
