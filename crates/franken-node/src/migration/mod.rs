//! Migration admission/progression controls.
//!
//! This module hosts deterministic migration policy gates used to decide
//! whether topology risk deltas are acceptable before and during rollout.

pub mod bpet_migration_gate;
pub mod dgis_migration_gate;
