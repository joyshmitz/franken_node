# bd-2zz Verification Summary: Dependency-Direction Guard

## Bead
- **ID:** bd-2zz
- **Title:** [10.1] Add dependency-direction guard preventing local engine crate reintroduction
- **Section:** 10.1 (Charter + Split Governance)

## Deliverables

| Artifact | Path | Status |
|----------|------|--------|
| Spec/contract | `docs/specs/section_10_1/bd-2zz_contract.md` | Created |
| Guard script | `scripts/guard_dependency_direction.py` | Created |
| Unit tests (9 tests) | `tests/test_guard_dependency_direction.py` | All pass |
| Verification evidence | `artifacts/section_10_1/bd-2zz/verification_evidence.json` | Generated |

## Guard Checks

| Check ID | Invariant | Result |
|----------|----------|--------|
| GUARD-WS-MEMBERS | No engine crate dirs in workspace members | PASS |
| GUARD-PKG-NAMES | No local Cargo.toml declares engine package names | PASS |
| GUARD-DEP-DIR | Engine deps point outside this repo to /dp/franken_engine/ | PASS |
| GUARD-CRATES-CLEAN | No engine-named dirs in crates/ | PASS |

## Unit Test Results

9/9 tests passing. Tests verify JSON output, verdict, all check IDs, individual checks, human-readable output, and summary counts.

**Overall Verdict: PASS (4/4 checks, 9/9 tests)**
