# bd-2ac: Secure Extension Distribution Network

**Section:** 10.0 | **Priority:** P1 | **Type:** task

## Objective

Build a signed extension registry and distribution network with end-to-end
integrity: signed packages, provenance attestation, revocation propagation,
and publisher reputation linkage.

## Key Modules

| Module | Path | Tests |
|--------|------|-------|
| Extension registry | `src/supply_chain/extension_registry.rs` | 42 |
| Artifact signing | `src/supply_chain/artifact_signing.rs` | 31 |
| Provenance | `src/supply_chain/provenance.rs` | 10 |
| Transparency verifier | `src/supply_chain/transparency_verifier.rs` | 23 |
| Revocation registry | `src/supply_chain/revocation_registry.rs` | 20 |
| Revocation integration | `src/supply_chain/revocation_integration.rs` | 16 |
| Reputation | `src/supply_chain/reputation.rs` | 23 |
| Trust card | `src/supply_chain/trust_card.rs` | 22 |
| CLI (registry subcommand) | `src/cli.rs` | — |

## Acceptance Criteria

1. **Signed extension package format** — `SignedExtension` with `ExtensionSignature`
   (Ed25519 via `AdmissionKernel`), `ProvenanceAttestation`, content integrity via
   SHA-256 content hashes, `manifest_bytes` for canonical signed payload.

2. **Registry publish/search/install** — `register()` publishes with signature
   verification, `query()`/`list()` search with status filtering, `add_version()`
   for version lineage, CLI `registry publish` / `registry search` commands.

3. **Revocation propagation** — `revoke()` with monotonic sequences,
   `RevocationRecord` with reason tracking, `revocation_registry.rs` for
   standalone revocation management, `revocation_integration.rs` for cross-module
   freshness checks.

4. **Publisher reputation linkage** — `reputation.rs` links publishers to trust
   scores, `trust_card.rs` binds cards to verified evidence with certification
   tiers, API routes for card search/comparison.

5. **Key-transparency and threshold-signing** — `transparency_verifier.rs` with
   Merkle inclusion proofs (`InclusionProof`), optional proof attachment on
   registration via `transparency_proof` field.

6. **Cryptographic decision receipts** — `AdmissionReceipt` with manifest digest,
   provenance level, `NegativeWitness` for rejection explanations.

7. **Signature/provenance verification at scale** — `AdmissionKernel.evaluate()`
   with configurable policies, batched provenance chain validation.

8. **CLI surface** — `franken-node registry publish` / `registry search` in
   `src/cli.rs` with `RegistryPublishArgs` and `RegistrySearchArgs`. Live
   `registry publish` must require operator-provided Ed25519 signing material;
   no deterministic demo key or hidden fallback is permitted in the publish
   path.

## Operator Signing Requirement

- `franken-node registry publish` requires `--signing-key <path>`.
- The key file must decode to a 32-byte Ed25519 private key.
- Human-readable publish output must report the resulting `publisher_key_id`
  and the signing-key source/path used for the registration.

## Invariants

- `INV-SER-SIGNED`: Every extension entry carries a verified Ed25519 signature.
- `INV-SER-PROVENANCE`: Provenance chain verified via canonical attestation verifier.
- `INV-SER-REVOCABLE`: Revocation is monotonic and irreversible.
- `INV-SER-MONOTONIC`: Version sequences strictly increase within lineage.
- `INV-SER-AUDITABLE`: Every mutation produces an immutable audit record.
- `INV-SER-DETERMINISTIC`: Same inputs produce same registry state.
- `INV-SER-NO-SHAPE-CHECKS`: No admission decision relies on field presence alone.

## Event Codes

- `SER-001` through `SER-011`: Registration, verification, provenance, versions, deprecation, revocation, lineage, audit export, integrity, query, admission.
- `SER-ERR-001` through `SER-ERR-007`: Invalid signature, missing provenance, already revoked, not found, key not found, provenance chain invalid, transparency failed.

## Dependencies Resolved

- `bd-1oju` (CLOSED): Trust cards bound to verified evidence
- `bd-3hdn` (CLOSED): Canonical signed-manifest admission kernel
- `bd-1ah` (CLOSED): Provenance attestation chain
- `bd-1gx` (CLOSED): Signed extension manifest schema
- `bd-yqz` (CLOSED): Fleet quarantine control plane
