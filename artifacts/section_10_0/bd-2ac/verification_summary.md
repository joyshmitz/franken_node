# bd-2ac: Secure Extension Distribution Network

**Section:** 10.0 | **Verdict:** PASS | **Date:** 2026-03-09

## Metrics

| Category | Count |
|----------|-------|
| Extension registry tests | 42 |
| Artifact signing tests | 31 |
| Transparency verifier tests | 23 |
| Reputation tests | 23 |
| Trust card tests | 22 |
| Revocation registry tests | 20 |
| Revocation integration tests | 16 |
| Provenance tests | 10 |
| **Total supply_chain tests** | **187** |

## Acceptance Criteria

| AC | Description | Status |
|----|-------------|--------|
| AC1 | Signed extension packages (Ed25519, provenance, content integrity) | PASS |
| AC2 | Registry publish/search/install with signature verification | PASS |
| AC3 | Revocation propagation with freshness checks | PASS |
| AC4 | Publisher reputation linkage to trust cards | PASS |
| AC5 | Key-transparency and Merkle inclusion proofs | PASS |
| AC6 | Cryptographic admission receipts with negative witnesses | PASS |
| AC7 | AdmissionKernel with batched verification pipeline | PASS |
| AC8 | CLI: `registry publish` / `registry search` | PASS |

## Gap Closures

| Bead | Description | Status |
|------|-------------|--------|
| bd-3hdn | Canonical signed-manifest admission kernel (replaces shape-only checks) | CLOSED |
| bd-1oju | Trust cards bound to verified evidence (not asserted inputs) | CLOSED |
