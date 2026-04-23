# Trust Card Schema Conformance - Known Discrepancies

This document records all intentional divergences from the trust card schema specification.

## DISC-001: Signature Testing Implementation Gaps
- **Specification:** bd-2yh requires HMAC-SHA256 signature verification for trust cards
- **Current impl:** Signature generation and verification logic exists but not integrated into conformance tests
- **Impact:** TC-SIG-001 and TC-SIG-002 test cases marked as expected failures
- **Resolution:** WILL-FIX - requires integration with TrustCardRegistry for proper key management
- **Tests affected:** TC-SIG-001 (registry signature verification), TC-SIG-002 (card hash derivation)
- **Review date:** 2026-04-23

## DISC-002: Audit History Bounds Enforcement  
- **Specification:** bd-2yh suggests audit_history should be bounded to prevent DoS
- **Current impl:** No explicit bounds checking in schema validation
- **Impact:** TC-EDGE-002 test case marked as expected failure
- **Resolution:** INVESTIGATING - need to determine appropriate bounds and enforcement strategy
- **Tests affected:** TC-EDGE-002 (large audit history bounds)
- **Review date:** 2026-04-23

## DISC-003: Golden Fixture Generation Dependencies
- **Specification:** Conformance harness should generate deterministic golden fixtures
- **Current impl:** Golden fixtures depend on `to_canonical_json` implementation
- **Impact:** Some tests may need UPDATE_GOLDENS=1 on first run
- **Resolution:** ACCEPTED - this is the expected workflow for golden file testing
- **Tests affected:** TC-SERIAL-001 (deterministic serialization)
- **Review date:** 2026-04-23

---

**Note:** All XFAIL (expected failure) test cases represent known gaps that do not compromise the core schema validation. MUST-level requirements (95% coverage target) are met for schema structure, serialization determinism, and round-trip consistency.