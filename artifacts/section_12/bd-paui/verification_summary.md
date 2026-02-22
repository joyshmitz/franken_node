# bd-paui Verification Summary

- Bead: `bd-paui`
- Section: `12`
- Capability: `Risk control: topological choke-point false positives`
- Verdict: `PASS`

## Scope Delivered

- Contract specification: `docs/specs/section_12/bd-paui_contract.md`
- Machine-readable report: `artifacts/12/chokepoint_false_positive_report.json`
- Verifier: `scripts/check_chokepoint_false_positives.py`
- Unit tests: `tests/test_check_chokepoint_false_positives.py`

## Acceptance Results

- Counterfactual simulation is enforced with replay size `>=1000` operations for all candidate rules.
- Enforced rules satisfy false-positive threshold (`<= 1%`); observed max enforced FP is `0.6%`.
- Enforced rules satisfy expected-loss net-positive condition.
- Staged rollout requirements are satisfied (`audit -> warn -> enforce`, minimum `24h` per stage).
- Audit stage is logs-only with zero blocked operations.

## Scenario Coverage

- Scenario A: 5% legitimate-block rule is rejected before enforcement.
- Scenario B: audit mode records violations but does not block operations.
- Scenario C: warn-to-enforce promotion only occurs for FP `<= 1%`.
- Scenario D: net-negative expected-loss rule is flagged and denied.

## Determinism and Adversarial Validation

- Aggregate evaluation is stable under rule-order permutations.
- Adversarial perturbation (enforced FP raised above `1%`) is detected and flips gate outcome.

## Reproducible Commands

```bash
python3 scripts/check_chokepoint_false_positives.py --self-test --json
python3 scripts/check_chokepoint_false_positives.py --json
python3 -m unittest tests/test_check_chokepoint_false_positives.py
```
