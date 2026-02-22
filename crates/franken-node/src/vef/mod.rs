pub mod constraint_compiler;
pub mod control_integration;
pub mod evidence_capsule;
pub mod proof_generator;
pub mod proof_scheduler;
pub mod proof_service;
pub mod proof_verifier;
pub mod receipt_chain;
pub mod sdk_integration;
pub mod verification_state;

// Re-export connector for sibling VEF modules so they can be compiled both
// from the crate root and from standalone test fixtures.
pub(crate) use crate::connector;
