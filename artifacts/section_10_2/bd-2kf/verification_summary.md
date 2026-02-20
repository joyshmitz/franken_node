# bd-2kf: Compatibility Mode Selection Policy — Verification Summary

## Verdict: PASS

## What was delivered

1. **Mode policy** `docs/COMPATIBILITY_MODE_POLICY.md`: 3 modes (strict, balanced, legacy-risky) with per-band behavior tables, default=balanced, unsafe opt-in rules, configuration format, enforcement rules
2. **Spec** `docs/specs/section_10_2/bd-2kf_contract.md`
3. **Verifier** `scripts/check_compat_modes.py`: 6 checks (MODE-EXISTS, MODE-DEFINED, MODE-DEFAULT, MODE-BANDS, MODE-UNSAFE, MODE-BANDS-REF)
4. **Tests** `tests/test_check_compat_modes.py`: 9 tests, all pass
