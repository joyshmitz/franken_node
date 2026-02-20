# Existing Node/Bun Structure

> Documents the existing structure of Node.js and Bun API surfaces
> that franken_node targets for compatibility.

**Status**: Template — to be populated per API family
**Purpose**: Reference material for spec extraction (NOT implementation blueprint)

---

## 1. Important Notice

Per [ADR-001](../adr/ADR-001-hybrid-baseline-strategy.md) and [IMPLEMENTATION_GOVERNANCE.md](../IMPLEMENTATION_GOVERNANCE.md):

> **This document is for specification extraction only. It is NOT an implementation blueprint.**
> Line-by-line translation from Node.js or Bun source is forbidden.

## 2. Node.js API Structure

### 2.1 Module Organization
- `lib/` — JavaScript API implementations
- `src/` — C++ bindings and native modules
- `deps/` — V8, libuv, OpenSSL, etc.

### 2.2 Core API Families
| Family | Node.js Location | Key Files |
|--------|-----------------|-----------|
| fs | `lib/fs.js`, `lib/internal/fs/` | readFile, writeFile, stat, mkdir |
| path | `lib/path.js` | join, resolve, parse, format |
| process | `lib/internal/process/` | env, argv, exit, cwd |
| http | `lib/http.js`, `lib/_http_*` | createServer, request |
| crypto | `lib/crypto.js`, `lib/internal/crypto/` | hash, hmac, cipher |

### 2.3 Bun Deviations
Key areas where Bun differs from Node.js:
- Bun.serve() vs http.createServer()
- Bun.file() for file operations
- Different default module resolution
- Performance-optimized hot paths

## 3. Behavioral Extraction Targets

For each API family, extract:
- **Data shapes**: Input/output types, optional parameters
- **Invariants**: Guaranteed behaviors regardless of input
- **Defaults**: Default values when parameters are omitted
- **Error semantics**: Error types, codes, messages
- **Edge cases**: Platform-specific behavior, encoding handling

## 4. References

- [Node.js Documentation](https://nodejs.org/api/)
- [Bun Documentation](https://bun.sh/docs)
- [PLAN_TO_PORT_NODE_BUN_SURFACES_TO_RUST.md](PLAN_TO_PORT_NODE_BUN_SURFACES_TO_RUST.md)
