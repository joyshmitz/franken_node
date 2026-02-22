# bd-2zl.3 support verification summary

## Scope
Expanded non-overlapping lockfile script regression coverage for `bd-2zl` in:
- `tests/test_transplant_lockfile_scripts.py`

## Added coverage
- generator rejects invalid `--generated-utc` values (exit 2)
- verifier emits `FAIL:PARSE` for malformed lockfile entry lines
- verifier emits `FAIL:COUNT` for lockfile header/entry count mismatch

## Validation
- Command: `python3 -m unittest tests/test_transplant_lockfile_scripts.py -v`
- Exit: `0`
- Result: `6/6` tests passed

## Notes
No edits were made to owner-reserved script/docs/hash files:
- `transplant/generate_lockfile.sh`
- `transplant/verify_lockfile.sh`
- `transplant/LOCKFILE_FORMAT.md`
- `transplant/TRANSPLANT_LOCKFILE.sha256`
- `docs/TODO_ULTRA_DETAILED.md`
