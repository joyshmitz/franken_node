# Known Conformance Divergences - Connector Lifecycle & API

This document tracks all intentional divergences from perfect cross-version compatibility
in the connector lifecycle and API conformance matrix.

## DISC-001: Three-Phase Cancellation Protocol (bd-1cs7)

- **Protocol:** Connector Lifecycle State Machine
- **Version introduced:** lifecycle-v1.2.0
- **Divergence:** Legacy versions (lifecycle-v1.1.0 and earlier) do not support the `Cancelling` state
- **Impact:** Old connectors cannot perform graceful three-phase cancellation (REQUEST→DRAIN→FINALIZE)
- **Resolution:** ACCEPTED - Legacy connectors use direct transition to `Stopped` state
- **Fallback behavior:** `Active`/`Paused` → `Stopped` (skip `Cancelling`)
- **Tests affected:** `test_backward_compatibility_state_transitions`
- **Review date:** 2026-04-20

## DISC-002: API Endpoint Versioning Scheme

- **Protocol:** REST API Endpoints
- **Version introduced:** api-v2.0.0
- **Divergence:** Path structure changed from `/api/v1/connector/transition` to `/api/v2/connector/lifecycle/transition`
- **Impact:** URL routing differs between API versions
- **Resolution:** ACCEPTED - Both endpoint patterns supported for backward compatibility
- **Fallback behavior:** Route mapping table maintains both URL schemes
- **Tests affected:** `test_api_endpoint_version_negotiation`
- **Review date:** 2026-04-20

## DISC-003: Frame Parser Resource Limits

- **Protocol:** Connector Frame Parser Configuration
- **Version introduced:** Ongoing evolution
- **Divergence:** Different versions have different default resource limits
  - Legacy: 100KB frames, 16 nesting depth, 50ms CPU
  - Current: 1MB frames, 32 nesting depth, 100ms CPU  
  - Future: 10MB frames, 64 nesting depth, 500ms CPU
- **Impact:** Larger frames may be rejected by legacy hosts
- **Resolution:** ACCEPTED - Negotiated limits used during capability exchange
- **Fallback behavior:** Use minimum common limits across versions
- **Tests affected:** `test_frame_parser_compatibility`
- **Review date:** 2026-04-20

## DISC-004: Session Authentication Methods

- **Protocol:** Session Authentication Protocol
- **Version introduced:** session-auth-v1.0.0
- **Divergence:** Authentication method capabilities vary by version
  - Legacy (v0.9.0): Basic session auth only
  - Current (v1.0.0): Basic + HMAC-SHA256 transcript-bound auth
  - Future (v1.1.0): Basic + HMAC + Mutual TLS
- **Impact:** Advanced authentication features unavailable with legacy hosts/connectors
- **Resolution:** ACCEPTED - Authentication method negotiated during handshake
- **Fallback behavior:** Use highest common authentication method
- **Tests affected:** `test_session_auth_protocol_evolution`
- **Review date:** 2026-04-20

## DISC-005: Feature Flag Compatibility

- **Protocol:** Connector Feature Capability Declaration
- **Version introduced:** Various
- **Divergence:** Feature flags not recognized across all versions
  - Legacy: `basic_lifecycle` only
  - Current: `basic_lifecycle`, `three_phase_cancellation`
  - Future: `basic_lifecycle`, `three_phase_cancellation`, `graceful_restart`, `hot_reload`
- **Impact:** Advanced features silently ignored by older versions
- **Resolution:** ACCEPTED - Feature intersection used for compatibility
- **Fallback behavior:** Operate using only commonly supported features
- **Tests affected:** `test_forward_compatibility_graceful_degradation`
- **Review date:** 2026-04-20

## DISC-006: Error Code Evolution

- **Protocol:** Lifecycle Error Response Codes
- **Version introduced:** Ongoing
- **Divergence:** Error code formats and granularity differ between versions
  - Legacy: Basic error messages with minimal structure
  - Current: Structured error codes with stable identifiers
  - Future: Enhanced error context with diagnostic hints
- **Impact:** Error handling logic must adapt to different error formats
- **Resolution:** ACCEPTED - Error code mapping layer provides consistent interface
- **Fallback behavior:** Map structured errors to basic error strings for legacy compatibility
- **Tests affected:** All compatibility tests with error scenarios
- **Review date:** 2026-04-20

## DISC-007: Connector State Transition Timing

- **Protocol:** State Transition Execution Timing
- **Version introduced:** Continuous evolution
- **Divergence:** Different versions have different timing characteristics for transitions
  - Legacy: Immediate state transitions (no async coordination)
  - Current: Asynchronous transitions with timeout handling
  - Future: Distributed consensus for state transitions
- **Impact:** Transition timing varies, affecting client timeout values
- **Resolution:** ACCEPTED - Timeout negotiation added to capability exchange
- **Fallback behavior:** Use conservative timeout values for legacy compatibility
- **Tests affected:** All transition timing tests
- **Review date:** 2026-04-20

## Version Compatibility Matrix Summary

| Connector Version | Host Version | Expected Compatibility | Known Issues |
|-------------------|--------------|----------------------|--------------|
| Legacy (v1.1.0)   | Current (v1.2.0) | Full | None (backward compatible) |
| Current (v1.2.0)  | Legacy (v1.1.0)  | Limited | No cancellation support |
| Future (v1.3.0)   | Current (v1.2.0) | Negotiated | Feature subset only |
| Current (v1.2.0)  | Future (v1.3.0)  | Full | All features supported |
| Legacy (v1.1.0)   | Future (v1.3.0)  | Limited | Multiple feature gaps |
| Future (v1.3.0)   | Legacy (v1.1.0)  | Negotiated | Significant fallback required |

## Review Schedule

- **Quarterly review:** Every 3 months, assess whether divergences are still needed
- **Version release review:** Before each major/minor version, review impact on compatibility
- **Annual audit:** Yearly comprehensive review of all documented divergences
- **Next review date:** 2026-07-20

## Adding New Divergences

When adding a new divergence:

1. Assign sequential ID (DISC-NNN)
2. Document the specific protocol/version affected
3. Clearly state impact and resolution
4. List all affected test cases
5. Set review date (max 6 months out)
6. Update compatibility matrix if needed
7. Mark tests as XFAIL (expected failure), not SKIP