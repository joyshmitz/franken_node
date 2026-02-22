# bd-1l5 Contract: Define Canonical Product Trust Object IDs with Domain Separation

**Bead:** bd-1l5
**Section:** 10.10 (FCP-Inspired Hardening)
**Status:** Active
**Owner:** CrimsonCrane
**Priority:** P2

## Overview

Enhancement Map 9E.1 mandates stable, collision-free identifiers for every trust
object in the franken_node system. This bead establishes a domain-separated prefix
scheme with deterministic derivation so that each trust object -- extension,
trust card, receipt, policy checkpoint, migration artifact, or verifier claim --
receives a globally unique, content-verifiable identifier. Cross-domain collisions
are structurally impossible because the domain prefix is baked into the hash input.

## Dependencies

- **Upstream:** bd-13q (stable error namespace for error codes)
- **Upstream:** bd-1hd (10.13 golden vector format conventions)
- **Downstream:** bd-jjm (deterministic serialization)
- **Downstream:** bd-174 (policy checkpoint chain)
- **Downstream:** bd-1jjq (section-wide verification gate)

## Data Model

### DomainPrefix (enum)

Six domain prefixes partition the trust object ID namespace:

| Variant            | Wire Prefix | Description                          |
|--------------------|-------------|--------------------------------------|
| Extension          | `ext:`      | Browser/runtime extensions           |
| TrustCard          | `tcard:`    | Trust attestation cards              |
| Receipt            | `rcpt:`     | Transaction/operation receipts       |
| PolicyCheckpoint   | `pchk:`     | Policy state checkpoints             |
| MigrationArtifact  | `migr:`     | Migration-produced artifacts         |
| VerifierClaim      | `vclaim:`   | Verifier-issued claims               |

### DerivationMode (enum)

| Variant           | Description                                               |
|-------------------|-----------------------------------------------------------|
| ContentAddressed  | ID derived solely from the canonical bytes of the object  |
| ContextAddressed  | ID derived from epoch + sequence + canonical bytes        |

### TrustObjectId (struct)

Canonical representation of a trust object identifier:

| Field            | Type              | Description                                      |
|------------------|-------------------|--------------------------------------------------|
| domain           | DomainPrefix      | Which domain this ID belongs to                  |
| hash_algorithm   | String            | Always `"sha256"`                                |
| digest           | String            | Hex-encoded SHA-256 digest (64 hex chars)        |
| derivation_mode  | DerivationMode    | How the digest was derived                       |
| epoch            | Option\<u64\>     | Present only for ContextAddressed derivation     |
| sequence         | Option\<u64\>     | Present only for ContextAddressed derivation     |

**Full-form wire format:** `{prefix}{digest}` (e.g. `ext:a1b2c3d4...64 hex chars`)

**Short-form display:** `{prefix}{first 8 hex chars}` (e.g. `ext:a1b2c3d4`)

### IdRegistry (struct)

Tracks all registered domain prefixes with version metadata:

| Field              | Type                              | Description                          |
|--------------------|-----------------------------------|--------------------------------------|
| prefixes           | HashMap\<String, DomainMeta\>     | Map of prefix string to metadata     |
| version            | u32                               | Registry schema version              |

Where `DomainMeta` contains:

| Field        | Type   | Description                        |
|--------------|--------|------------------------------------|
| variant      | String | Enum variant name                  |
| description  | String | Human-readable description         |
| registered   | u64    | Unix timestamp of registration     |

The default `IdRegistry::new()` constructor pre-registers all 6 domain prefixes.

### IdError (enum)

| Variant          | Error Code               | Description                                          |
|------------------|--------------------------|------------------------------------------------------|
| InvalidPrefix    | ERR_TOI_INVALID_PREFIX   | Prefix string does not match any DomainPrefix variant|
| MalformedDigest  | ERR_TOI_MALFORMED_DIGEST | Digest is not exactly 64 lowercase hex characters    |
| InvalidFormat    | ERR_TOI_INVALID_FORMAT   | Wire string does not match `{prefix}{hex64}` form    |
| UnknownDomain    | ERR_TOI_UNKNOWN_DOMAIN   | Domain prefix not found in the IdRegistry            |

## Key Methods

### TrustObjectId

- **`TrustObjectId::derive_content_addressed(domain: DomainPrefix, data: &[u8]) -> Self`**
  Computes `sha256(canonical_bytes(domain_prefix || data))` and returns a
  ContentAddressed TrustObjectId. The domain prefix bytes are prepended to the
  data before hashing, ensuring cross-domain collision resistance.

- **`TrustObjectId::derive_context_addressed(domain: DomainPrefix, epoch: u64, sequence: u64, data: &[u8]) -> Self`**
  Computes `sha256(canonical_bytes(domain_prefix || epoch_be_bytes || sequence_be_bytes || data))`
  and returns a ContextAddressed TrustObjectId with epoch and sequence set.

- **`TrustObjectId::parse(s: &str) -> Result<Self, IdError>`**
  Parses a full-form wire string (e.g. `ext:abcdef01...`) back into a
  TrustObjectId. Returns `IdError::InvalidFormat` if the string does not match
  the expected pattern, `IdError::InvalidPrefix` if the prefix is not
  recognized, or `IdError::MalformedDigest` if the hex portion is invalid.

- **`TrustObjectId::validate(s: &str) -> bool`**
  Convenience wrapper: returns `true` if `parse(s)` succeeds, `false` otherwise.

- **`TrustObjectId::full_form(&self) -> String`**
  Returns the complete wire-format string: `{prefix}{64-char hex digest}`.

- **`TrustObjectId::short_form(&self) -> String`**
  Returns a display-friendly truncated form: `{prefix}{first 8 hex chars}`.

### IdRegistry

- **`IdRegistry::new() -> Self`**
  Creates a registry pre-populated with all 6 domain prefixes and their metadata.

- **`IdRegistry::is_valid_prefix(s: &str) -> bool`**
  Returns `true` if the given string (e.g. `"ext:"`) is a registered prefix.

### Free Functions

- **`canonical_bytes(data: &[u8]) -> Vec<u8>`**
  Deterministic serialization of input data. For trust object ID derivation this
  ensures byte-identical output regardless of platform or serialization order.

- **`sha256_digest(data: &[u8]) -> String`**
  Computes SHA-256 over `data` and returns the lowercase hex-encoded digest
  (64 characters).

## Invariants

| Invariant ID         | Statement                                                       |
|----------------------|-----------------------------------------------------------------|
| INV-TOI-PREFIX       | Every TrustObjectId has a valid domain prefix from the 6-variant enum. An ID cannot be constructed without one. |
| INV-TOI-DETERMINISTIC| Given identical inputs (domain, data, and optionally epoch+sequence), `derive_content_addressed` and `derive_context_addressed` always produce the same TrustObjectId. |
| INV-TOI-COLLISION    | Cross-domain collisions are structurally impossible because the domain prefix bytes are included in the hash preimage. Two objects with different DomainPrefix values cannot produce the same digest even if their payloads are identical. |
| INV-TOI-DIGEST       | The digest field is always a 256-bit SHA-256 hash encoded as exactly 64 lowercase hexadecimal characters. No shorter or weaker hashes are permitted. |

## Event Codes

| Code    | Severity | Description                                       |
|---------|----------|---------------------------------------------------|
| TOI-001 | INFO     | Trust object ID derived successfully               |
| TOI-002 | WARN     | Trust object ID validation failed                  |

## Error Codes

| Code                      | Description                                              |
|---------------------------|----------------------------------------------------------|
| ERR_TOI_INVALID_PREFIX    | Prefix string does not match any registered DomainPrefix |
| ERR_TOI_MALFORMED_DIGEST  | Digest is not 64 lowercase hex characters                |
| ERR_TOI_INVALID_FORMAT    | Wire-format string does not match `{prefix}{hex64}`      |
| ERR_TOI_UNKNOWN_DOMAIN    | Domain prefix not found in IdRegistry                    |

## Acceptance Criteria

1. **6 domain prefixes registered:** `IdRegistry::new()` contains all 6 prefixes
   (`ext:`, `tcard:`, `rcpt:`, `pchk:`, `migr:`, `vclaim:`) and
   `is_valid_prefix` returns `true` for each.
2. **Two derivation modes:** Both `derive_content_addressed` and
   `derive_context_addressed` produce valid TrustObjectIds with the correct
   `derivation_mode` field.
3. **Parse/validate round-trip:** For every domain prefix, an ID produced by
   `derive_*` can be serialized with `full_form()`, parsed back with `parse()`,
   and the result equals the original.
4. **Cross-domain collision impossible:** Two calls with the same `data` but
   different `DomainPrefix` values produce distinct digests. This is verified by
   exhaustive pairwise comparison across all 6 prefixes.
5. **Short-form and full-form:** `full_form()` returns the complete
   `{prefix}{64 hex chars}` string; `short_form()` returns `{prefix}{8 hex chars}`.
6. **Deterministic derivation:** Calling `derive_content_addressed` (or
   `derive_context_addressed`) twice with identical inputs produces byte-identical
   output.
7. **256-bit SHA-256 collision resistance:** The `digest` field is always exactly
   64 hex characters (256 bits). Parsing rejects any string with a shorter or
   malformed digest with `IdError::MalformedDigest`.

## Verification

- Script: `scripts/check_trust_object_ids.py --json`
- Tests: `tests/test_check_trust_object_ids.py`
- Evidence: `artifacts/section_10_10/bd-1l5/verification_evidence.json`
- Summary: `artifacts/section_10_10/bd-1l5/verification_summary.md`

## Artifacts

| Artifact                                                        | Purpose                        |
|-----------------------------------------------------------------|--------------------------------|
| `docs/specs/section_10_10/bd-1l5_contract.md`                  | This specification document    |
| `crates/franken-node/src/connector/trust_object_id.rs`          | Rust implementation            |
| `scripts/check_trust_object_ids.py`                             | Verification script (--json)   |
| `tests/test_check_trust_object_ids.py`                          | Unit tests for verifier        |
| `artifacts/section_10_10/bd-1l5/verification_evidence.json`     | Machine-readable evidence      |
| `artifacts/section_10_10/bd-1l5/verification_summary.md`        | Human-readable summary         |
