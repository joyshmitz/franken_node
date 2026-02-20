# Proposed Architecture

> Defines how Node/Bun API surfaces are implemented natively on
> franken_engine with trust-native architecture.

**Status**: Template — to be refined as implementation progresses
**Authority**: [ADR-001: Hybrid Baseline Strategy](../adr/ADR-001-hybrid-baseline-strategy.md)

---

## 1. Architecture Principles

### 1.1 Native Implementation
All compatibility behavior is implemented natively on franken_engine + asupersync. No binding-based execution core.

### 1.2 Policy-Visible Compatibility
Every compatibility shim is typed, tracked in the behavior registry, and produces policy-visible events.

### 1.3 Trust-Native Integration
Compatibility implementations integrate with franken_engine's trust primitives:
- Capability-gated resource access
- Cryptographic attestation for operations
- Deterministic replay support
- Audit trail for all policy-relevant behavior

## 2. Layer Architecture

```
┌─────────────────────────────────────┐
│         JS/TS API Surface           │  ← Node/Bun-compatible APIs
├─────────────────────────────────────┤
│     Compatibility Shim Layer        │  ← Typed shims with registry entries
├─────────────────────────────────────┤
│    Policy Enforcement Layer         │  ← Band-aware divergence handling
├─────────────────────────────────────┤
│      franken_engine Interface       │  ← Engine trust boundary (L2 oracle)
├─────────────────────────────────────┤
│        franken_engine Core          │  ← Native execution substrate
└─────────────────────────────────────┘
```

## 3. Shim Types

| Type | Description | Trust Level |
|------|-------------|-------------|
| `native` | Direct engine implementation | Full trust |
| `polyfill` | Pure JS/TS implementation | Sandboxed |
| `bridge` | Bridge between JS and engine | Mediated trust |
| `stub` | Placeholder returning error | No trust required |

## 4. Per-Family Architecture Notes

_To be populated as each API family is implemented._

| Family | Architecture Approach | Key Decisions |
|--------|----------------------|---------------|
| fs | Engine-native with capability gates | Permission-scoped paths |
| path | Pure Rust implementation | No engine dependency needed |
| process | Bridge to engine process model | Sanitized env access |
| http | Engine-native server + JS routing | Policy-visible connections |

## 5. References

- [ENGINE_SPLIT_CONTRACT.md](../ENGINE_SPLIT_CONTRACT.md)
- [COMPATIBILITY_BANDS.md](../COMPATIBILITY_BANDS.md)
- [COMPATIBILITY_REGISTRY.json](../COMPATIBILITY_REGISTRY.json)
