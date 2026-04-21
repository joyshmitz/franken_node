# Known Frankensqlite Conformance Divergences

## Overview

This file documents any intentional deviations between the bd-1a1j contract specification 
and the actual frankensqlite adapter implementation. All divergences must be explicitly 
documented and regularly reviewed.

## Current Status

**No known divergences** - The golden files were generated directly from the current 
`canonical_classes()` implementation, so full conformance is expected.

## Future Divergence Documentation Template

When divergences are discovered, document them using this format:

### DISC-001: Example Divergence Title
- **Reference**: What the bd-1a1j contract specifies
- **Our impl**: What the frankensqlite adapter actually does
- **Impact**: How this affects behavior or interoperability
- **Resolution**: ACCEPTED | INVESTIGATING | WILL-FIX
- **Tests affected**: List of conformance test IDs that use XFAIL for this divergence
- **Review date**: When this divergence should be re-evaluated

## Review Schedule

- **Monthly**: Review all INVESTIGATING divergences for resolution
- **Quarterly**: Review all ACCEPTED divergences to ensure they're still valid
- **On contract updates**: Review all divergences when bd-1a1j contract changes

## Test Failure Protocol

When a conformance test fails:

1. **Investigate root cause** - Is this a real divergence or a test infrastructure issue?
2. **Classify impact** - Does this break contract compatibility?
3. **Document if intentional** - Add to this file if the divergence is accepted
4. **Update test status** - Use `TestStatus::ExpectedFailure` for accepted divergences
5. **Set review date** - Schedule follow-up evaluation

## Compliance Targets

- **MUST requirements**: 100% compliance required (no accepted divergences allowed)
- **SHOULD requirements**: ≥95% compliance target (limited accepted divergences allowed)
- **MAY requirements**: No compliance target (divergences allowed)

---

*Last updated: 2026-04-21 - Initial creation with no known divergences*