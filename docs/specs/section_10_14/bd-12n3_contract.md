# bd-12n3 Contract: Epoch-Bound Idempotency Keys

## Scope
Define deterministic idempotency-key derivation for retryable remote control requests.

## Derivation Function
`derive_key(computation_name, epoch, request_bytes) -> IdempotencyKey`

Canonical input bytes:
1. `domain_prefix` (`franken_node.idempotency.v1`)
2. separator byte `0x1F`
3. UTF-8 `computation_name`
4. separator byte `0x1F`
5. `epoch` encoded as big-endian `u64`
6. separator byte `0x1F`
7. raw `request_bytes`

Digest: `SHA-256(canonical_input)`

## Security Properties
- Deterministic: identical inputs produce identical outputs.
- Domain separated: different computation names produce different keys.
- Epoch bound: same computation + payload across different epochs yields different keys.
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
