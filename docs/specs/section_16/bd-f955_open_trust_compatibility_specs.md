# bd-f955 Open Trust and Compatibility Specification Contract

## Scope

This contract defines how `franken_node` publishes open, reproducible trust and
compatibility specifications so external operators and independent verifiers can
evaluate behavior without private context.

## Publication Surface

- Canonical spec path: `docs/specs/section_16/bd-f955_open_trust_compatibility_specs.md`
- Canonical machine artifact: `artifacts/16/open_trust_compatibility_specs.json`
- Section evidence path: `artifacts/section_16/bd-f955/verification_evidence.json`
- Every release must include immutable version tags and changelog links.

## Compatibility Contract Matrix

The compatibility matrix must publish behavior commitments for:

- API compatibility per interface class (control-plane, data-plane, policy-plane).
- Storage compatibility per on-disk schema version and migration requirements.
- Security compatibility per policy profile (`balanced`, `strict`).
- Evidence compatibility per artifact schema version and canonicalization rules.

## Trust Evidence Contract

Published trust specifications must include:

- Signed provenance references for every high-impact claim.
- Deterministic replay artifact requirements for trust decisions.
- Open JSON schema references for claims, errors, and evidence ledgers.

## Determinism and Reproducibility Requirements

- Re-running the checker against identical inputs must produce byte-identical JSON output.
- Required event-code and invariant coverage must be machine-verifiable.
- Missing required sections, codes, or schema links must fail release gates.

## Release Gate Contract

Release claims for open trust/compatibility specs are blocked unless all checks pass:

- `python3 scripts/check_open_trust_compat_specs.py --json`
- `python3 -m unittest tests/test_check_open_trust_compat_specs.py`

## Event Codes

- `OTCS-001`: specification bundle published
- `OTCS-002`: compatibility matrix validated
- `OTCS-003`: trust provenance requirements satisfied
- `OTCS-004`: release gate decision emitted

## Invariants

- `INV-OTCS-OPEN`: all required spec artifacts are in public repository paths.
- `INV-OTCS-COMPAT`: compatibility matrix covers required contract dimensions.
- `INV-OTCS-TRUST`: trust requirements include signed provenance and deterministic replay.
- `INV-OTCS-DETERMINISTIC`: checker output is deterministic for identical inputs.

## Governance

- Any schema or compatibility contract change requires a spec version bump.
- Deprecated compatibility behavior must include explicit sunset dates.
- Gate violations must be emitted as structured events and recorded in section evidence.
