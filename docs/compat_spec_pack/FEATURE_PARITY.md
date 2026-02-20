# Feature Parity Tracker

> Tracks implementation progress toward Node.js/Bun feature parity,
> organized by API family, band, and implementation status.

**Status**: Template — updated as features are implemented
**Authority**: [ADR-001: Hybrid Baseline Strategy](../adr/ADR-001-hybrid-baseline-strategy.md)
**Data Source**: [COMPATIBILITY_REGISTRY.json](../COMPATIBILITY_REGISTRY.json)

---

## 1. Overall Status

| Metric | Value |
|--------|-------|
| Total tracked behaviors | 5 |
| Implemented (native/polyfill/bridge) | 0 |
| Stubbed | 5 |
| Core band coverage | 0% |
| High-value band coverage | 0% |

## 2. By API Family

### 2.1 fs (Core)
| API | Band | Status | Oracle |
|-----|------|--------|--------|
| readFile | core | stub | pending |
| writeFile | core | stub | pending |

### 2.2 path (Core)
| API | Band | Status | Oracle |
|-----|------|--------|--------|
| join | core | stub | pending |

### 2.3 process (Core)
| API | Band | Status | Oracle |
|-----|------|--------|--------|
| env | core | stub | pending |

### 2.4 http (High-Value)
| API | Band | Status | Oracle |
|-----|------|--------|--------|
| createServer | high-value | stub | pending |

## 3. Release Gate Targets

| Milestone | Core Target | High-Value Target |
|-----------|-------------|-------------------|
| Alpha | >= 50% | >= 25% |
| Beta | >= 95% | >= 80% |
| GA | 100% | >= 95% |

## 4. Known Divergences

See [DIVERGENCE_LEDGER.json](../DIVERGENCE_LEDGER.json) for accepted divergences.

## 5. References

- [COMPATIBILITY_BANDS.md](../COMPATIBILITY_BANDS.md)
- [COMPATIBILITY_REGISTRY.json](../COMPATIBILITY_REGISTRY.json)
- [PLAN_TO_PORT_NODE_BUN_SURFACES_TO_RUST.md](PLAN_TO_PORT_NODE_BUN_SURFACES_TO_RUST.md)
