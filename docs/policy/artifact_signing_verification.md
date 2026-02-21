# Artifact Signing and Verification Policy

**Bead:** bd-2pw | **Section:** 10.6
**Effective:** 2026-02-20

## 1. Scope

This policy governs the signing, checksum generation, verification, and key
management for all franken_node release artifacts. It applies to binaries,
configuration bundles, compliance evidence archives, and any other
distributable artifact.

## 2. Signing Workflow

### 2.1 Individual Artifact Signing

1. For each release artifact, compute its SHA-256 checksum.
2. Sign the artifact bytes with the current Ed25519 signing key.
3. Write the detached signature to `<artifact>.sig`.
4. Emit audit log entry with event code `ASV-001`.

### 2.2 Manifest Generation

1. Collect all artifacts and their SHA-256 checksums.
2. Write `SHA256SUMS` in canonical format: `<sha256>  <name>  <size>\n`,
   entries sorted lexicographically by filename.
3. Sign the canonical manifest bytes with the current Ed25519 signing key.
4. Write the manifest signature to `SHA256SUMS.sig`.

### 2.3 Threshold Signing (when configured)

1. Distribute the canonical manifest bytes to N authorized key holders.
2. Each key holder signs independently, producing a `PartialSignature` with
   their `KeyId`.
3. The release system collects partial signatures.
4. Duplicate signers (same `KeyId`) are rejected.
5. Once M valid distinct signatures are collected (M <= N), the release is
   authorized.
6. The first valid signature set is recorded; individual `.sig` files use
   the primary release key.

## 3. Key Management

### 3.1 Key Generation

- Keys are Ed25519, generated outside the repository.
- Private keys are stored in CI secrets or HSM references; they never appear
  in source control.
- Public keys are stored in a key directory, one file per key, named by key ID.

### 3.2 Key ID Derivation

A key ID is the first 8 bytes of the SHA-256 hash of the 32-byte Ed25519
public key, hex-encoded (16 characters).

### 3.3 Key Rotation

1. Generate a new Ed25519 key pair.
2. Create a key-transition record: old key signs endorsement of new key.
3. Verify the transition record.
4. Add the new public key to the key directory.
5. The old key remains valid for artifacts signed before the rotation.
6. Emit audit log entry with event code `ASV-004`.

### 3.4 Key Revocation

If a key is compromised:
1. Remove the private key from all signing systems immediately.
2. Do NOT remove the public key from the key directory (old signatures must
   remain verifiable for audit purposes).
3. Issue a new key and create a transition record.
4. Re-sign any artifacts signed with the compromised key if feasible.

## 4. Checksum Manifest Format

```
<sha256-hex>  <filename>  <size-bytes>
```

- SHA-256 hex: 64 lowercase hex characters.
- Two-space separator between fields.
- Filename: relative path within the release directory.
- Size: decimal byte count.
- One entry per line, LF line endings.
- Entries sorted lexicographically by filename.

## 5. Verification Protocol

`franken-node verify release <path>` performs:

1. **Manifest signature check**: Load `SHA256SUMS` and `SHA256SUMS.sig`.
   Verify the signature against the key ring. Fail if invalid.
2. **Checksum verification**: For each entry in the manifest, compute
   SHA-256 of the corresponding file. Fail if any hash mismatches.
3. **Individual signature check**: For each artifact with a `.sig` file,
   verify the detached Ed25519 signature. Fail if any is invalid.
4. **Output**: Structured JSON with:
   - `manifest_signature_ok`: boolean.
   - `results`: array of per-artifact `{ artifact_name, passed, key_id, failure_reason }`.
   - `overall_pass`: boolean (true only if all checks pass).
5. **Exit code**: 0 on full success, non-zero on any failure.
6. **Audit**: Emit `ASV-002` for each passing artifact, `ASV-003` for each failure.

## 6. CI Release Gate

The release pipeline MUST:

1. Run `franken-node verify release <staging-dir>` against the staged release.
2. Block publication if the command exits non-zero.
3. Record the verification report as a CI artifact.

## 7. Invariants

| ID              | Policy Requirement                                                            |
|-----------------|-------------------------------------------------------------------------------|
| INV-ASV-SIG     | Every `.sig` file is a valid Ed25519 detached signature.                      |
| INV-ASV-MANIFEST| The `SHA256SUMS` manifest is complete and correct.                            |
| INV-ASV-MSIG    | The `SHA256SUMS.sig` is a valid Ed25519 signature over canonical manifest.    |
| INV-ASV-KEYID   | Every signature is associated with a deterministic key ID.                    |
| INV-ASV-ROTATE  | Key rotation uses signed transition records.                                  |
| INV-ASV-THRESH  | Threshold signing rejects duplicate signers and requires M distinct valid sigs.|
| INV-ASV-TAMPER  | Any byte modification causes verification failure.                            |
| INV-ASV-AUDIT   | Every operation emits a structured audit log entry.                           |

## 8. Exceptions

No exceptions. All release artifacts MUST be signed and checksum-verified
before distribution. Unsigned artifacts MUST NOT be published.
