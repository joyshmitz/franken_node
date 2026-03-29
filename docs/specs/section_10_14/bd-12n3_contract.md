# bd-12n3 Contract: Epoch-Bound Idempotency Keys

## Scope
Define deterministic idempotency-key derivation for retryable remote control requests.

## Derivation Function
`derive_key(computation_name, epoch, request_bytes) -> IdempotencyKey`

Canonical input bytes:
1. `len(domain_prefix)` encoded as big-endian `u64`
2. `domain_prefix` (`franken_node.idempotency.v1`)
3. `len(computation_name_utf8)` encoded as big-endian `u64`
4. UTF-8 `computation_name`
5. `epoch` encoded as big-endian `u64`
6. `len(request_bytes)` encoded as big-endian `u64`
7. raw `request_bytes`

Digest: `SHA-256("idempotency_key_derive_v1:" || canonical_input)`

## Security Properties
- Deterministic: identical inputs produce identical outputs.
- Domain separated: different computation names produce different keys.
- Epoch bound: same computation + payload across different epochs yields different keys.
- Injective framing: length prefixes prevent tuple aliasing when computation names or payloads contain control bytes such as `0x1F`.
- Collision resistance: empirical check over 10,000+ generated payloads must report zero collisions.

## Registry Integration
`derive_registered_key(...)` validates the computation name against
`ComputationRegistry` before deriving a key.

## Event Codes
- `IK_KEY_DERIVED`
- `IK_DERIVATION_ERROR`
- `IK_VECTOR_VERIFIED`
- `IK_COLLISION_CHECK_PASSED`

## Evidence Artifacts
- `artifacts/10.14/idempotency_vectors.json`
- `tests/conformance/idempotency_key_derivation.rs`
- `artifacts/section_10_14/bd-12n3/verification_evidence.json`
- `artifacts/section_10_14/bd-12n3/verification_summary.md`
