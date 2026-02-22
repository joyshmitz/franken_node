# bd-2177: High-Impact Workflow Primitive Mapping

**Section:** 10.15 | **Bead:** bd-2177 | **Schema:** wfm-v1.0

## Objective

Map all high-impact franken_node control-plane workflows to canonical
asupersync primitives so that downstream planning gates can verify
primitive coverage deterministically.

## Deliverables

| Artifact | Path | Status |
|----------|------|--------|
| Architecture doc | `docs/architecture/high_impact_workflow_map.md` | Complete |
| Matrix JSON | `artifacts/10.15/workflow_primitive_matrix.json` | Complete |
| Check script | `scripts/check_workflow_primitive_map.py` | PASS |
| Test suite | `tests/test_check_workflow_primitive_map.py` | 12/12 PASS |
| Spec contract | `docs/specs/section_10_15/bd-2177_contract.md` | This file |
| Evidence | `artifacts/section_10_15/bd-2177/verification_evidence.json` | Complete |
| Summary | `artifacts/section_10_15/bd-2177/verification_summary.md` | Complete |

## Canonical Primitive Vocabulary (7)

Sourced from `docs/architecture/tri_kernel_ownership_contract.md` frontmatter
key `canonical_asupersync_primitives`:

1. `cx_propagation`
2. `region_ownership_scope`
3. `cancellation_protocol`
4. `obligation_tracking`
5. `remote_computation_registry`
6. `epoch_validity_window`
7. `evidence_ledger_emission`

## Required Workflows (8)

| Workflow ID | Name |
|-------------|------|
| `connector_lifecycle` | Connector Lifecycle Orchestration |
| `rollout_state_transitions` | Rollout State Transitions |
| `health_gate_evaluation` | Health-Gate Evaluation |
| `publish_flow` | Publish Flow |
| `revoke_flow` | Revoke Flow |
| `quarantine_promotion` | Quarantine Promotion |
| `migration_orchestration` | Migration Orchestration |
| `fencing_token_acquisition_release` | Fencing Token Acquisition and Release |

## Gate Checks (12)

| Check | Event Code | Description |
|-------|------------|-------------|
| contract_exists | -- | Tri-kernel ownership contract exists |
| matrix_exists | -- | workflow_primitive_matrix.json exists |
| io_and_parse | -- | Both files load without error |
| canonical_primitives_loaded | -- | 7 primitives extracted from frontmatter |
| workflows_is_list | -- | Matrix workflows field is an array |
| workflow_entry_shapes | -- | All entries are objects |
| required_workflows_present | -- | All 8 required workflows found |
| critical_workflow_primitive_coverage | WFM-001 | Each required workflow lists all 7 primitives |
| primitive_references_known | WFM-004 | No unknown primitive references |
| critical_workflows_mapped_or_exceptioned | WFM-001/002/003 | All workflows mapped or exception-approved |
| summary_counts_consistent | -- | Summary matches computed counts |
| canonical_vocab_alignment | -- | Script primitives match contract primitives |

## Exception Policy

Unmapped critical workflows require an approved exception object:
- `approved: true`
- `waiver_id`: string
- `reason`: string
- `expires_at`: RFC3339 timestamp (must be in the future)

Expired exceptions are treated as unapproved.
