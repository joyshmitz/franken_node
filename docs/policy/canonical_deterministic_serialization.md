# Canonical Deterministic Serialization Policy

**Policy ID:** POL-CAN-001
**Section:** 10.10 (FCP-Inspired Hardening)
**Bead:** bd-jjm
**Effective:** 2026-02-21
**Owner:** CrimsonCrane

## 1. Purpose

This policy establishes the rules for canonical deterministic serialization
and signature preimage construction across all trust-critical data structures
in the franken_node product. It ensures that every signed trust artifact
serializes to exactly one byte sequence for any given logical value, and
that signature preimage computation follows a single canonical path.

## 2. Scope

Applies to all trust object types that participate in signing or
verification within the three-kernel architecture (franken_engine,
asupersync, franken_node):

- Policy checkpoints (`PolicyCheckpoint`, domain tag `0x1001`)
- Delegation tokens (`DelegationToken`, domain tag `0x1002`)
- Revocation assertions (`RevocationAssertion`, domain tag `0x1003`)
- Session tickets (`SessionTicket`, domain tag `0x1004`)
- Zone boundary claims (`ZoneBoundaryClaim`, domain tag `0x1005`)
- Operator receipts (`OperatorReceipt`, domain tag `0x1006`)

## 3. Definitions

- **Canonical Serialization:** A deterministic byte encoding where the same
  logical value always produces byte-identical output, regardless of field
  insertion order, platform, or thread.
- **Signature Preimage:** The exact byte sequence fed to a cryptographic
  signature function, consisting of `[version][domain_tag][canonical_payload]`.
- **Domain-Separation Tag:** A two-byte prefix in every signature preimage
  that prevents cross-type signature confusion attacks.
- **Round-Trip Canonical:** The property that serialize -> deserialize ->
  re-serialize produces byte-identical output.
- **Golden Vector:** A reference test vector that defines the expected
  canonical output for a known input, used for cross-implementation
  validation.

## 4. Invariants

### INV-CAN-DETERMINISTIC
Same logical value produces identical bytes on every serialization call.
Two calls to `serialize()` with the same `object_type` and `payload` must
return byte-identical output regardless of call ordering, thread, or
platform.

### INV-CAN-NO-FLOAT
No IEEE 754 floating-point values may appear in serialized trust artifacts.
`serialize()` rejects any payload containing float or double fields with
`FloatingPointRejected`. This prevents non-deterministic rounding and
NaN-related ambiguity.

### INV-CAN-DOMAIN-TAG
Every signature preimage includes a two-byte domain-separation tag.
`SignaturePreimage::to_bytes()` always prefixes the canonical payload with
`[version][domain_tag]`, and `build()` rejects zero-valued domain tags.

### INV-CAN-NO-BYPASS
All signing routes pass through `CanonicalSerializer`. No code path may
construct a `SignaturePreimage` from non-canonical bytes. Static analysis
and code review must confirm this property.

## 5. Serialization Rules

1. **Length-Prefixed Binary Format:** All payloads are encoded as 4-byte
   big-endian length prefix followed by the payload bytes.
2. **No Floating-Point:** JSON payloads containing `number.number` patterns
   outside of string contexts are rejected.
3. **Sorted Keys:** For JSON payloads, all object keys are sorted
   lexicographically before serialization.
4. **Schema Registration:** Every trust object type must have a registered
   `CanonicalSchema` with a defined field ordering and domain tag before
   serialization is permitted.
5. **Version Prefix:** Schema version is embedded in the preimage format to
   support future schema evolution.

## 6. Preimage Construction

The signature preimage is constructed as:
```
[version: 1 byte] || [domain_tag: 2 bytes] || [canonical_payload: N bytes]
```

This layout ensures:
- Version-awareness for future upgrades
- Domain separation to prevent cross-type signature reuse
- Canonical payload bytes for deterministic verification

## 7. Event Codes

| Code                   | Severity | Trigger                             |
|------------------------|----------|-------------------------------------|
| CAN_SERIALIZE          | INFO     | Successful canonical serialization  |
| CAN_PREIMAGE_CONSTRUCT | INFO     | Successful preimage construction    |
| CAN_REJECT             | WARN     | Serialization or preimage rejected  |

All events include `trace_id` for correlation.

## 8. Error Codes

| Code                          | Condition                             |
|-------------------------------|---------------------------------------|
| ERR_CAN_NON_CANONICAL         | Input not in canonical form           |
| ERR_CAN_SCHEMA_NOT_FOUND      | No schema for requested object type   |
| ERR_CAN_FLOAT_REJECTED        | Payload contains floating-point value |
| ERR_CAN_PREIMAGE_FAILED       | Invalid version or zero domain tag    |
| ERR_CAN_ROUND_TRIP_DIVERGENCE | Round-trip produced different bytes    |

## 9. Compliance

- All new signing code paths MUST use `CanonicalSerializer`.
- Code reviews MUST verify no bypass of the canonical serializer.
- CI gates MUST validate golden vectors on every build.
- Property tests MUST verify round-trip stability across 1000+ inputs.

## 10. References

- Enhancement Map 9E.2: Deterministic serialization contracts
- bd-3n2u: Golden vectors from Section 10.13
- bd-1l5: Canonical trust object IDs with domain separation
- bd-174: Policy checkpoint chain (downstream consumer)
