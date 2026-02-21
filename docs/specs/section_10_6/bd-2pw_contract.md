# bd-2pw: Artifact Signing and Checksum Verification for Releases

## Bead: bd-2pw | Section: 10.6

## Purpose

Supply-chain integrity is a first-class requirement for franken_node (Section 9I.9).
Every release artifact -- binary, configuration bundle, compliance evidence archive --
must be cryptographically signed so that consumers can verify authenticity and detect
tampering before installation. This bead establishes the signing infrastructure,
verification CLI, and CI gates that enforce integrity for all release artifacts.

## Signing Scheme

- **Algorithm**: Ed25519 (via `ed25519-dalek` crate).
- **Detached signatures**: Each artifact gets a `.sig` file containing a raw Ed25519
  signature over the artifact bytes.
- **Checksum manifest**: A `SHA256SUMS` file lists every artifact with its SHA-256
  hash and size. The manifest itself is signed, producing `SHA256SUMS.sig`.
- **Two-layer verification**: consumers verify (1) the manifest signature against
  a trusted public key, then (2) each file's SHA-256 hash against the manifest.

## Acceptance Criteria

1. Every release artifact has a corresponding `.sig` (detached Ed25519 signature) and
   is listed in a signed `SHA256SUMS` manifest.
2. `franken-node verify release <path>` validates manifest signature, individual
   checksums, and individual signatures, exiting non-zero on any failure.
3. Verification output is structured JSON with per-artifact pass/fail status, key ID
   used, and failure reason if applicable.
4. CI release gate blocks publication of unsigned or checksum-mismatched artifacts.
5. Threshold signing is supported when configured (requires M-of-N partial signatures
   to produce a valid release signature).
6. Key rotation is supported via signed transition records; old keys remain valid for
   artifacts signed before rotation.
7. Verification script `scripts/check_artifact_signing.py` with `--json` flag
   validates the signing infrastructure.
8. Unit tests in `tests/test_check_artifact_signing.py` cover signature generation,
   verification, checksum computation, manifest parsing, key rotation, and threshold
   signing logic.

## Event Codes

| Code    | When Emitted                                                   |
|---------|----------------------------------------------------------------|
| ASV-001 | Artifact signed: emitted after successful signing of one artifact. |
| ASV-002 | Verification succeeded: emitted when artifact passes all checks.   |
| ASV-003 | Verification failed: emitted with failure reason when any check fails. |
| ASV-004 | Key rotated: emitted after a key-transition record is created and validated. |

## Invariants

| ID              | Statement                                                                           |
|-----------------|-------------------------------------------------------------------------------------|
| INV-ASV-SIG     | Every release artifact's `.sig` is a valid Ed25519 detached signature over the artifact bytes. |
| INV-ASV-MANIFEST| The `SHA256SUMS` manifest lists every artifact with a correct SHA-256 hash and size.  |
| INV-ASV-MSIG    | The `SHA256SUMS.sig` is a valid Ed25519 signature over the canonical manifest bytes. |
| INV-ASV-KEYID   | Every signature embeds (or is associated with) a key ID derived from the public key. |
| INV-ASV-ROTATE  | Key rotation is performed via a signed transition record: old key endorses new key.   |
| INV-ASV-THRESH  | Threshold signing requires M-of-N distinct valid partial signatures; duplicates are rejected. |
| INV-ASV-TAMPER  | Modifying any byte of a signed artifact causes verification to fail with a clear error. |
| INV-ASV-AUDIT   | Every signing and verification operation emits a structured JSON audit log entry.     |

## Quantitative Targets

| Metric                           | Target                              |
|----------------------------------|-------------------------------------|
| Signature size                   | 64 bytes (Ed25519)                  |
| Key ID length                    | 16 hex chars (8 bytes of SHA-256)   |
| SHA-256 hash length              | 64 hex chars (32 bytes)             |
| Threshold minimum                | 2-of-N (configurable)               |
| Manifest format                  | `<sha256>  <name>  <size>\n`        |

## Manifest Format

```text
a1b2c3d4...  franken-node-v1.0.tar.gz  10485760
e5f6a7b8...  policy-bundle-v1.0.json   2048
```

Each line: hex-encoded SHA-256, two spaces, filename, two spaces, size in bytes,
newline. Lines are sorted lexicographically by filename.

## Key Transition Record

A key rotation produces a transition record containing:
- `old_key_id`: ID of the retiring key.
- `new_key_id`: ID of the incoming key.
- `new_public_key_bytes`: 32-byte Ed25519 public key.
- `timestamp`: Unix epoch seconds.
- `signature`: Ed25519 signature by the old key over the canonical payload.

Verification of the transition record proves the old key holder authorized the new key.

## Threshold Signing Protocol

When threshold signing is configured:
1. Each of N key holders signs the manifest independently, producing a `PartialSignature`.
2. The release system collects partial signatures and validates each against the key ring.
3. Duplicate signers (same key ID) are rejected.
4. Once M valid distinct partial signatures are collected, the release is authorized.

## Dependencies

- `ed25519-dalek` (already in Cargo.toml).
- `sha2` (already in Cargo.toml).
- 10.13 fencing protocol (optional, for threshold signing integration).

## Implementation

- `crates/franken-node/src/supply_chain/artifact_signing.rs` -- core module.
- CLI: `franken-node verify release <path>` via `cli.rs` `VerifyCommand::Release`.
- Wired in `main.rs` via `handle_verify_release`.
