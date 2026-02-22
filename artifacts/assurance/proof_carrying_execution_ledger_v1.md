# Proof-Carrying Execution Ledger (PCEL) v1

- Bead: `bd-2hqd.4`
- Verdict: `PASS`
- Generated: `2026-02-22T22:32:01Z`
- Scope: `prefix:bd-2hqd`
- Selected closed beads: `4`
- Full proof beads: `4`
- Merkle root: `d599b4e0e610c81bcf9cc4987f0a3cf0fc33cf197616483c70170f64e27086fc`

## Gate Checks

| Check | Pass | Detail |
|-------|------|--------|
| PCEL-SCOPE-NONEMPTY | PASS | selected_closed_beads=4 scope=prefix:bd-2hqd |
| PCEL-PROOF-COMPLETE | PASS | full_proof=4 total=4 missing_evidence=0 missing_summary=0 invalid_evidence_json=0 |
| PCEL-DEP-CLOSURE | PASS | missing_dependency_proofs=0 |
| PCEL-DEP-SCOPE-COMPLETE | PASS | out_of_scope_closed_dependencies=0 |
| PCEL-DEP-RESOLVED | PASS | unresolved_dependency_references=0 |
| PCEL-MERKLE-ROOT | PASS | leaf_count=4 depth=3 root=d599b4e0e610c81bcf9cc4987f0a3cf0fc33cf197616483c70170f64e27086fc |
| PCEL-CANONICAL-DETERMINISM | PASS | json.dumps(sort_keys=True,separators=(',',':'),ensure_ascii=True) |

## Included Beads

| Bead | Artifact Dir | Evidence | Summary | Leaf |
|------|--------------|----------|---------|------|
| bd-2hqd | artifacts/section_10_17/bd-2hqd | yes | yes | 36e974392052098e... |
| bd-2hqd.1 | artifacts/section_10_17/bd-2hqd.1 | yes | yes | b3ae092abd4e927c... |
| bd-2hqd.2 | artifacts/section_10_17/bd-2hqd.2 | yes | yes | 2ea4b3f85f003a94... |
| bd-2hqd.3 | artifacts/section_bootstrap/bd-2hqd.3 | yes | yes | 37739a23ac136416... |
