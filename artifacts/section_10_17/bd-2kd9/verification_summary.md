# bd-2kd9: Claim Compiler and Public Trust Scoreboard Pipeline — Verification Summary

## Bead Identity

| Field | Value |
|-------|-------|
| Bead ID | bd-2kd9 |
| Section | 10.17 — Radical Expansion Execution Track |
| Verdict | PASS |

## Implementation Summary

This bead implements the claim compiler and public trust scoreboard pipeline for
the franken_node radical expansion track. The pipeline provides:

1. **Claim Compiler** (`ClaimCompiler`) — validates, normalises, and compiles
   raw external claims into `CompiledClaim` evidence contracts. Unverifiable
   claim text is rejected at compile time (fail-closed).

2. **Trust Scoreboard** — aggregates compiled claims into a deterministic,
   signed `ScoreboardSnapshot`. Updates are atomic (all-or-nothing). Every
   snapshot carries a SHA-256 digest binding entries to the scoreboard state.

3. **TrustScoreboard** — read-only view for external consumption, created from
   a `ScoreboardSnapshot`.

## Key Types

| Type | Purpose |
|------|---------|
| `ClaimCompiler` | Main pipeline: compile claims, publish batches, take snapshots |
| `TrustScoreboard` | Read-only public view of scoreboard state |
| `CompiledClaim` | Output of successful compilation |
| `ScoreEntry` | Single entry on the scoreboard |
| `ClaimSource` | Source metadata for a claim |
| `EvidenceLink` | URI-based link to supporting evidence |
| `RawClaim` | Input submitted for compilation |
| `ScoreboardSnapshot` | Signed snapshot of all entries |
| `ClaimCompilerEvent` | Structured audit event |
| `ClaimCompilerError` | Error type with stable error codes |

## Invariants Verified

| Invariant | Status |
|-----------|--------|
| INV-CLMC-FAIL-CLOSED | Verified — empty text, missing source, no evidence all rejected |
| INV-CLMC-EVIDENCE-LINKED | Verified — compiled claims always have evidence links |
| INV-CLMC-SCOREBOARD-ATOMIC | Verified — partial batch failures roll back completely |
| INV-CLMC-DETERMINISTIC | Verified — BTreeMap ordering, identical digests from identical inputs |
| INV-CLMC-SIGNED-EVIDENCE | Verified — SHA-256 digest on every snapshot |
| INV-CLMC-SCHEMA-VERSIONED | Verified — schema version on all outputs |
| INV-CLMC-AUDIT-COMPLETE | Verified — event codes emitted for every decision |

## Event Codes

10 event codes (CLMC_001 through CLMC_010) covering claim submission,
compilation success/rejection, scoreboard update lifecycle, evidence link
validation, and snapshot signing.

## Error Codes

8 error codes (ERR_CLMC_*) covering all rejection paths: empty claim text,
missing source, no evidence links, invalid evidence URI, duplicate claim ID,
scoreboard full, digest mismatch, and unknown schema version.

## Test Coverage

- **32 Rust inline unit tests** covering all error variants, invariants,
  deterministic replay, atomic rollback, digest verification, and audit events.
- **15 Python unit tests** in `tests/test_check_claim_compiler.py` verifying
  the checker script's verdict, shape, event/error/invariant counts, CLI
  behaviour, and self-test.
- **53 checker checks** in `scripts/check_claim_compiler.py` verifying
  implementation tokens, event codes, error codes, invariants, and artifacts.

## Deliverables

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_17/bd-2kd9_contract.md` |
| Rust module | `crates/franken-node/src/connector/claim_compiler.rs` |
| Check script | `scripts/check_claim_compiler.py` |
| Test suite | `tests/test_check_claim_compiler.py` |
| Evidence | `artifacts/section_10_17/bd-2kd9/verification_evidence.json` |
| Summary | `artifacts/section_10_17/bd-2kd9/verification_summary.md` |
