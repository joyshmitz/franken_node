# bd-1naf Verification Summary

## Scope
Defined BPET governance policy for thresholding, appeals, and evidence-backed override workflows.

## Delivered
- Spec contract: `docs/specs/section_10_21/bd-1naf_contract.md`
- Policy: `docs/policy/bpet_governance_policy.md`
- Rust audit fixture tests: `tests/policy/bpet_override_audit.rs`
- Checker script: `scripts/check_bpet_governance.py`
- Checker unit tests: `tests/test_check_bpet_governance.py`
- Governance audit log sample: `artifacts/10.21/bpet_governance_audit_log.jsonl`
- Evidence JSON: `artifacts/section_10_21/bd-1naf/verification_evidence.json`
- This summary: `artifacts/section_10_21/bd-1naf/verification_summary.md`

## Verification Commands
- `python3 -m py_compile scripts/check_bpet_governance.py tests/test_check_bpet_governance.py`
- `python3 scripts/check_bpet_governance.py --self-test`
- `python3 -m unittest tests/test_check_bpet_governance.py`
- `python3 scripts/check_bpet_governance.py --json`

## Result
- Verdict: **PASS**
- Checks: **14/14 passed**

## Acceptance Mapping
- Explicit threshold, false-positive, appeal, and override workflows documented.
- Signed rationale requirement enforced in policy and checked in audit log validation.
- Override bounds (TTL + dual-control for T3 requests) validated.
- Hard-stop non-overridable clause explicitly present.
- Structured audit trail includes stable `BPET-GOV-*` event codes and trace-linked entries.
