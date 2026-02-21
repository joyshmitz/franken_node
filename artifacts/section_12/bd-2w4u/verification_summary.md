# bd-2w4u Verification Summary

- Bead: `bd-2w4u`
- Section: `12`
- Capability: `Risk control: hardening perf regression`
- Verdict: `PASS`

## Scope Delivered

- Contract specification: `docs/specs/section_12/bd-2w4u_contract.md`
- Machine-readable report: `artifacts/12/hardening_perf_regression_report.json`
- Verifier: `scripts/check_hardening_perf_regression.py`
- Unit tests: `tests/test_check_hardening_perf_regression.py`

## Acceptance Results

- Three hardening profiles (`strict`, `balanced`, `permissive`) are present with explicit performance tradeoffs.
- Balanced profile p99 overhead is `14.0%` versus baseline (threshold: `<= 15%`).
- Balanced profile throughput retention is `87.0%` versus baseline (threshold: `>= 85%`).
- Runtime profile switching is reconfigurable without restart and with `0` request failures under load.
- Continuous benchmarking contract is enforced: regressions above `5%` are blocked in CI.

## Scenario Coverage

- Scenario A: strict profile overhead is benchmarked and documented (informational).
- Scenario B: balanced profile passes p99 and throughput release gates.
- Scenario C: injected `20%` latency regression is blocked by CI.
- Scenario D: runtime profile switching under load completes with no request failures.

## Determinism and Adversarial Validation

- Order-insensitive aggregate recomputation is stable.
- Adversarial perturbation (balanced p99 raised to 25% overhead) flips the p99 gate as expected.

## Reproducible Commands

```bash
python3 scripts/check_hardening_perf_regression.py --self-test --json
python3 scripts/check_hardening_perf_regression.py --json
python3 -m unittest tests/test_check_hardening_perf_regression.py
```
