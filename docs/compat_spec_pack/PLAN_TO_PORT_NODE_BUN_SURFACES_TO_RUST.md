# Plan to Port Node/Bun Surfaces to Rust

> Strategic plan for extracting and reimplementing Node.js/Bun API surfaces
> using the spec-first hybrid baseline strategy.

**Status**: Template — to be populated per API family
**Authority**: [ADR-001: Hybrid Baseline Strategy](../adr/ADR-001-hybrid-baseline-strategy.md)
**Governance**: [IMPLEMENTATION_GOVERNANCE.md](../IMPLEMENTATION_GOVERNANCE.md)

---

## 1. Scope

This document defines the porting plan for Node.js/Bun API surfaces to native Rust implementations on franken_engine. Each API family section follows the Spec-First Essence Extraction Protocol.

## 2. Methodology

### 2.1 Spec-First Extraction
1. Identify target API surface and compatibility band
2. Extract behavioral specification from Node.js documentation and source
3. Generate conformance fixtures using Node.js/Bun as oracle
4. Implement from spec + fixture contracts — not from source structure
5. Validate against L1 lockstep oracle

### 2.2 Prioritization
- **Phase 1**: Core band APIs (fs, path, process, Buffer, streams)
- **Phase 2**: High-value band APIs (http, crypto, child_process, timers)
- **Phase 3**: Edge band APIs (as needed for adoption)

## 3. API Family Porting Status

| Family | Band | Phase | Spec Status | Impl Status | Oracle Status |
|--------|------|-------|-------------|-------------|---------------|
| fs | core | 1 | pending | stub | pending |
| path | core | 1 | pending | stub | pending |
| process | core | 1 | pending | stub | pending |
| Buffer | core | 1 | pending | stub | pending |
| streams | core | 1 | pending | stub | pending |
| http | high-value | 2 | pending | stub | pending |
| crypto | high-value | 2 | pending | stub | pending |

## 4. Release Gate

This porting plan is release-gated:
- Phase 1 completion required for alpha release
- Phase 2 completion required for beta release
- Core band pass rate >= 100% required at all milestones
- High-value band pass rate >= 95% required for beta

## 5. References

- [COMPATIBILITY_BANDS.md](../COMPATIBILITY_BANDS.md)
- [L1_LOCKSTEP_RUNNER.md](../L1_LOCKSTEP_RUNNER.md)
- [COMPATIBILITY_REGISTRY.json](../COMPATIBILITY_REGISTRY.json)
