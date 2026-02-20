# bd-2hs: Four-Doc Spec Pack

## Decision Rationale

The canonical plan (Section 10.2, Section 5.4) requires a four-document spec pack for compatibility extraction. These documents follow the porting-to-rust Spec-First Essence Extraction Protocol and are release-gated.

## Documents

1. `PLAN_TO_PORT_NODE_BUN_SURFACES_TO_RUST.md` — Porting plan with methodology and status
2. `EXISTING_NODE_BUN_STRUCTURE.md` — Reference structure (NOT implementation blueprint)
3. `PROPOSED_ARCHITECTURE.md` — Native implementation architecture
4. `FEATURE_PARITY.md` — Feature parity tracker

## Invariants

1. All 4 documents exist in `docs/compat_spec_pack/`.
2. Each document references the hybrid baseline strategy.
3. EXISTING_NODE_BUN_STRUCTURE includes the "not implementation blueprint" warning.
4. FEATURE_PARITY tracks per-family, per-band status.
5. PLAN_TO_PORT includes release gate targets.
