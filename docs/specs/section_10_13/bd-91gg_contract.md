# bd-91gg: Background Repair Controller

## Purpose

Bounded work-per-cycle repair with fairness controls. No tenant starvation under load. Controller decisions are auditable.

## Invariants

- **INV-BRC-BOUNDED**: Total repair work per cycle never exceeds the configured cap.
- **INV-BRC-FAIRNESS**: Every tenant with pending repairs gets at least one unit per cycle (no starvation).
- **INV-BRC-AUDITABLE**: Every cycle produces an audit record with tenant-level breakdown.
- **INV-BRC-DETERMINISTIC**: Same pending repairs + same config → same allocation.

## Types

### RepairConfig

Per-cycle work cap, fairness_minimum per tenant, max_tenants_per_cycle.

### RepairItem

Pending repair: item_id, tenant_id, priority, size_units.

### RepairAllocation

Per-tenant allocation: tenant_id, items_allocated, units_used.

### RepairCycleAudit

Audit record: cycle_id, allocations, total_units_used, cap, skipped tenants, trace_id.

### BackgroundRepairController

Controller: `run_cycle(pending, config)` → `(Vec<RepairAllocation>, RepairCycleAudit)`.

## Error Codes

- `BRC_CAP_EXCEEDED` — attempted to exceed per-cycle work cap
- `BRC_INVALID_CONFIG` — config has invalid values
- `BRC_NO_PENDING` — no pending repairs
- `BRC_STARVATION` — fairness violation detected
