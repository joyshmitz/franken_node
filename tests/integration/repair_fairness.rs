//! Integration tests for bd-91gg: Background repair controller fairness.

use frankenengine_node::connector::repair_controller::*;

fn item(id: &str, tenant: &str, priority: u32, size: u64) -> RepairItem {
    RepairItem { item_id: id.into(), tenant_id: tenant.into(), priority, size_units: size }
}

fn config() -> RepairConfig {
    RepairConfig { max_units_per_cycle: 100, fairness_minimum: 5, max_tenants_per_cycle: 10 }
}

#[test]
fn inv_brc_bounded() {
    let items: Vec<RepairItem> = (0..50).map(|i| item(&format!("r{i}"), "t1", 5, 10)).collect();
    let (_, audit) = run_cycle(&items, &config(), "c1", "tr", "ts").unwrap();
    assert!(audit.total_units_used <= config().max_units_per_cycle, "INV-BRC-BOUNDED violated");
}

#[test]
fn inv_brc_fairness() {
    let items = vec![
        item("r1", "t1", 10, 3),
        item("r2", "t1", 9, 3),
        item("r3", "t2", 1, 3),
        item("r4", "t3", 1, 3),
    ];
    let (allocs, _) = run_cycle(&items, &config(), "c1", "tr", "ts").unwrap();
    for alloc in &allocs {
        assert!(!alloc.items_allocated.is_empty(), "INV-BRC-FAIRNESS: tenant {} starved", alloc.tenant_id);
    }
}

#[test]
fn inv_brc_auditable() {
    let items = vec![item("r1", "t1", 5, 10), item("r2", "t2", 3, 10)];
    let (_, audit) = run_cycle(&items, &config(), "cycle-1", "trace-x", "2026-01-01").unwrap();
    assert_eq!(audit.cycle_id, "cycle-1");
    assert_eq!(audit.trace_id, "trace-x");
    assert!(!audit.allocations.is_empty(), "INV-BRC-AUDITABLE: must have allocation records");
}

#[test]
fn inv_brc_deterministic() {
    let items = vec![
        item("r1", "t1", 5, 10),
        item("r2", "t2", 3, 10),
        item("r3", "t1", 8, 10),
    ];
    let (a1, _) = run_cycle(&items, &config(), "c1", "tr", "ts").unwrap();
    let (a2, _) = run_cycle(&items, &config(), "c1", "tr", "ts").unwrap();
    for (x, y) in a1.iter().zip(a2.iter()) {
        assert_eq!(x.tenant_id, y.tenant_id, "INV-BRC-DETERMINISTIC violated");
        assert_eq!(x.units_used, y.units_used);
    }
}
