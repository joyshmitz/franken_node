# Claim Compiler & Public Trust Scoreboard Pipeline (bd-2kd9)

## Scope

This contract governs the compilation of external claims into executable
evidence contracts and the publication of signed scoreboard snapshots in
`franken_node`. Unverifiable claim text is blocked at compile time, and
scoreboard updates carry signed evidence links.

## Core Invariants

- `INV-CLAIM-EXECUTABLE-CONTRACT`: every accepted claim compiles to an executable evidence contract.
- `INV-CLAIM-BLOCK-UNVERIFIABLE`: claims without verifiable evidence are rejected at compile time.
- `INV-SCOREBOARD-SIGNED-EVIDENCE`: scoreboard updates publish signed evidence links with SHA-256 digests.
- `INV-SCOREBOARD-FRESH-LINKS`: scoreboard evidence links must reference non-stale artifacts.

## Claim Compilation Rules

1. Claim text must be non-empty and syntactically valid.
2. Claim must reference at least one evidence source URI.
3. Evidence URIs must be well-formed and reachable at compile time.
4. Claims without verifiable evidence produce `ERR_CLAIM_UNVERIFIABLE` and are blocked.
5. Invalid claim syntax produces `ERR_CLAIM_SYNTAX_INVALID`.
6. Missing evidence links produce `ERR_CLAIM_EVIDENCE_MISSING`.
7. Successfully compiled claims emit `CLAIM_CONTRACT_GENERATED`.

## Scoreboard Pipeline Rules

1. Scoreboard snapshots are atomic: partial updates never become visible.
2. Each snapshot carries a SHA-256 signed digest for tamper detection.
3. Evidence links must be fresh (not stale beyond the configured threshold).
4. Invalid signatures on scoreboard entries produce `ERR_SCOREBOARD_SIGNATURE_INVALID`.
5. Stale evidence references produce `ERR_SCOREBOARD_STALE_EVIDENCE`.
6. Successful publication emits `SCOREBOARD_UPDATE_PUBLISHED` and `SCOREBOARD_EVIDENCE_SIGNED`.

## Compiled Claim Schema

Required fields:

- `claim_id`
- `claim_text`
- `evidence_uris` (non-empty list)
- `source_id`
- `compiled_at_epoch_ms`
- `contract_digest`
- `signer_id`
- `signature`

## Scoreboard Entry Schema

Required fields:

- `entry_id`
- `claim_id`
- `trust_score`
- `evidence_link`
- `signed_digest`
- `published_at_epoch_ms`

## Event Codes

- `CLAIM_COMPILATION_START`
- `CLAIM_CONTRACT_GENERATED`
- `CLAIM_VERIFICATION_LINKED`
- `SCOREBOARD_UPDATE_PUBLISHED`
- `SCOREBOARD_EVIDENCE_SIGNED`

## Error Codes

- `ERR_CLAIM_UNVERIFIABLE`
- `ERR_CLAIM_SYNTAX_INVALID`
- `ERR_CLAIM_EVIDENCE_MISSING`
- `ERR_CLAIM_BLOCKED`
- `ERR_SCOREBOARD_SIGNATURE_INVALID`
- `ERR_SCOREBOARD_STALE_EVIDENCE`

## Required Artifacts

- `crates/franken-node/src/claims/mod.rs`
- `crates/franken-node/src/claims/claim_compiler.rs`
- `tests/conformance/claim_compiler_gate.rs`
- `artifacts/10.17/public_trust_scoreboard_snapshot.json`
