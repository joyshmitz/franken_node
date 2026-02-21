# Verification Summary: External-Reproduction Playbook and Automation Scripts

**Bead:** bd-2pu | **Section:** 10.7
**Date:** 2026-02-20
**Verdict:** PASS

## Metrics

| Metric | Value |
|--------|-------|
| Total checks | 91 |
| Passed | 91 |
| Failed | 0 |
| Unit tests | 48 |
| Unit tests passed | 48 |

## Coverage Summary

| Category | Checks | Status |
|----------|--------|--------|
| File existence (spec, policy, playbook, claims, script) | 5 | PASS |
| Spec event codes (ERP-001 to ERP-004) | 4 | PASS |
| Spec invariants (INV-ERP-COMPLETE, REPLAY, ENVIRONMENT, DETERMINISM) | 4 | PASS |
| Spec sections (playbook, automation, claims, report, acceptance) | 5 | PASS |
| Spec error codes (ERR_ERP_*) | 4 | PASS |
| Policy sections (format, automation, environment, seed, claims, CI, determinism, events) | 8 | PASS |
| Policy event codes | 4 | PASS |
| Policy governance keywords | 6 | PASS |
| Playbook sections (environment, fixtures, execution, comparison, troubleshooting) | 5 | PASS |
| Playbook environment keywords | 6 | PASS |
| Playbook commands | 3 | PASS |
| Playbook variance keywords | 3 | PASS |
| Claims format fields | 5 | PASS |
| Claims entry count (>=5) | 1 | PASS |
| Claims categories (compatibility, security, performance, migration, trust) | 5 | PASS |
| Claims IDs (HC-001 to HC-005) | 5 | PASS |
| Script features (skip-install, dry-run, json, yes, claim, fingerprint, report, idempotent) | 8 | PASS |
| Script report fields (environment, claims, verdict, timestamp, duration) | 5 | PASS |
| Script environment fingerprint fields (os, cpu, python, rust, node) | 5 | PASS |

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_7/bd-2pu_contract.md` |
| Policy document | `docs/policy/external_reproduction.md` |
| Reproduction playbook | `docs/reproduction_playbook.md` |
| Headline claims registry | `docs/headline_claims.toml` |
| Automation script | `scripts/reproduce.py` |
| Verification script | `scripts/check_external_reproduction.py` |
| Unit tests | `tests/test_check_external_reproduction.py` |
| Verification evidence | `artifacts/section_10_7/bd-2pu/verification_evidence.json` |
| Verification summary | `artifacts/section_10_7/bd-2pu/verification_summary.md` |
