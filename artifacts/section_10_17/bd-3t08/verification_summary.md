# Section 10.17 Verification Gate — bd-3t08

## Verdict: FAIL

## Why It Fails

The gate checker now cross-checks live Beads state from `.beads/issues.jsonl` instead of trusting stale PASS artifacts alone. The current 10.17 section cannot close yet because:

- `bd-nbwo` is still `open` and is blocked by `bd-1z5a`
- `bd-2kd9` is still `open` and is blocked by `bd-1z5a` and `bd-nbwo`
- `bd-2o8b` still carries a live blocker edge to `bd-nbwo`, so its old PASS artifact is no longer enough to keep the section gate green

## Current Live Blocker Chain

| Bead | Live Status | Gate Result | Blocking Chain |
|------|-------------|-------------|----------------|
| bd-nbwo | open | FAIL | `bd-1z5a` |
| bd-2o8b | closed | FAIL | `bd-nbwo` |
| bd-2kd9 | open | FAIL | `bd-1z5a`, `bd-nbwo` |

All other section-10.17 upstream beads remain closed with passing evidence.

## Gate Checks

- **56/65** checks passed
- **9/65** checks failed
- Stale PASS artifacts are now rejected when live bead status or blocker edges say the section is still open
- Section artifacts and summary files are still present, but the section verdict is intentionally fail-closed

### Failing Checks

- `evidence_bd-nbwo`
- `evidence_bd-2o8b`
- `evidence_bd-2kd9`
- `all_verdicts_pass`
- `all_upstream_beads_closed`
- `all_upstream_blockers_closed`
- `domain_verifier_sdk_coverage`
- `domain_hardware_planner_coverage`
- `domain_claim_compiler_coverage`

## Invariants

Validated:
- `INV-GATE-EVIDENCE-COMPLETE`
- `INV-GATE-ARTIFACT-PRESENT`
- `INV-GATE-SCHEMA-VERSIONED`

Blocked:
- `INV-GATE-ALL-PASS`
- `INV-GATE-DOMAIN-COVERAGE`

## Verification Method

```bash
python3 scripts/check_section_10_17_gate.py --json
python3 scripts/check_section_10_17_gate.py --self-test
python3 -m unittest tests/test_check_section_10_17_gate.py
```
