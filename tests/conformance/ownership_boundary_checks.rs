//! Conformance gate for tri-kernel ownership boundaries (bd-1id0).
//!
//! Enforces:
//! - parseable ownership contract frontmatter
//! - deterministic module ownership classification
//! - boundary crossing detection with signed + non-expired waivers only
//! - machine-readable ownership report artifacts

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const OWN_001: &str = "OWN-001";
const OWN_002: &str = "OWN-002";
const OWN_003: &str = "OWN-003";
const OWN_004: &str = "OWN-004";

#[derive(Debug, Clone, Deserialize)]
struct ContractFrontmatter {
    schema_version: String,
    bead_id: String,
    section: String,
    kernels: BTreeMap<String, KernelSpec>,
    hard_runtime_invariant_owners: BTreeMap<String, String>,
    permitted_cross_kernel_interfaces: Vec<String>,
    waiver_policy: WaiverPolicySpec,
    structured_event_codes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct KernelSpec {
    plane: String,
    owns: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct WaiverPolicySpec {
    registry_path: String,
    required_fields: Vec<String>,
    expiry_enforced: bool,
    unsigned_allowed: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct WaiverRegistry {
    schema_version: String,
    waivers: Vec<WaiverRecord>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct WaiverRecord {
    #[serde(default)]
    waiver_id: String,
    #[serde(default)]
    file: String,
    #[serde(default)]
    boundary: String,
    #[serde(default)]
    rationale: String,
    #[serde(default)]
    signed_by: String,
    #[serde(default)]
    signature: String,
    #[serde(default)]
    expires_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum KernelPlane {
    Execution,
    Correctness,
    Product,
}

#[derive(Debug, Clone, Serialize)]
struct BoundaryViolation {
    rule_id: String,
    event_code: String,
    file: String,
    boundary: String,
    reason: String,
    waived: bool,
}

#[derive(Debug, Clone, Serialize)]
struct OwnershipBoundaryReport {
    schema_version: String,
    bead_id: String,
    generated_on: String,
    modules_scanned: usize,
    modules_by_plane: BTreeMap<String, usize>,
    boundary_results: BTreeMap<String, String>,
    active_violations: Vec<BoundaryViolation>,
    waived_violations: Vec<BoundaryViolation>,
    invalid_waivers: Vec<WaiverRecord>,
    expired_waivers: Vec<WaiverRecord>,
}

#[derive(Debug, Serialize)]
struct VerificationEvidence {
    bead_id: &'static str,
    gate: &'static str,
    generated_on: String,
    status: &'static str,
    modules_scanned: usize,
    active_violations: usize,
    waived_violations: usize,
    invalid_waivers: usize,
    expired_waivers: usize,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn parse_frontmatter(md: &str) -> Result<ContractFrontmatter, String> {
    if !md.starts_with("---\n") {
        return Err("missing YAML frontmatter start".to_string());
    }
    let Some(rest) = md.strip_prefix("---\n") else {
        return Err("invalid frontmatter prefix".to_string());
    };
    let Some((yaml, _body)) = rest.split_once("\n---\n") else {
        return Err("missing YAML frontmatter terminator".to_string());
    };
    serde_yaml::from_str::<ContractFrontmatter>(yaml).map_err(|e| format!("frontmatter parse failed: {e}"))
}

fn classify_module(relative_module_path: &str) -> KernelPlane {
    if relative_module_path.starts_with("runtime/")
        || relative_module_path.starts_with("remote/")
        || relative_module_path.starts_with("connector/")
    {
        return KernelPlane::Execution;
    }
    if relative_module_path.starts_with("control_plane/")
        || relative_module_path.starts_with("security/")
        || relative_module_path.starts_with("policy/")
        || relative_module_path.starts_with("conformance/")
    {
        return KernelPlane::Correctness;
    }
    KernelPlane::Product
}

fn detect_product_boundary_violations(relative_path: &str, src: &str) -> Vec<BoundaryViolation> {
    let mut out = Vec::new();

    let forbidden_correctness_imports = [
        "crate::control_plane::internal::",
        "crate::security::internal::",
        "crate::policy::controller_boundary_checks",
        "crate::runtime::lane_scheduler",
    ];

    for pattern in forbidden_correctness_imports {
        if src.contains(pattern) {
            out.push(BoundaryViolation {
                rule_id: "OWN-RULE-001".to_string(),
                event_code: OWN_002.to_string(),
                file: relative_path.to_string(),
                boundary: "product->correctness-internal".to_string(),
                reason: format!("forbidden import pattern `{pattern}`"),
                waived: false,
            });
        }
    }

    let forbidden_execution_redefinitions = [
        "pub struct CancellationState",
        "pub enum SchedulerLane",
        "pub struct EpochBarrier",
    ];

    for marker in forbidden_execution_redefinitions {
        if src.contains(marker) {
            out.push(BoundaryViolation {
                rule_id: "OWN-RULE-002".to_string(),
                event_code: OWN_002.to_string(),
                file: relative_path.to_string(),
                boundary: "product-reimplements-execution-primitive".to_string(),
                reason: format!("detected ownership marker `{marker}`"),
                waived: false,
            });
        }
    }

    out
}

fn waiver_is_valid(waiver: &WaiverRecord, now: DateTime<Utc>) -> Result<(), String> {
    if waiver.file.trim().is_empty() {
        return Err("waiver missing file".to_string());
    }
    if waiver.boundary.trim().is_empty() {
        return Err("waiver missing boundary".to_string());
    }
    if waiver.signed_by.trim().is_empty() {
        return Err("waiver missing signed_by".to_string());
    }
    if waiver.signature.trim().is_empty() {
        return Err("waiver missing signature".to_string());
    }
    let expiry = waiver
        .expires_at
        .parse::<DateTime<Utc>>()
        .map_err(|e| format!("waiver expiry parse failed: {e}"))?;
    if expiry < now {
        return Err("waiver expired".to_string());
    }
    Ok(())
}

fn collect_rust_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| format!("failed to read directory {}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("failed to read directory entry: {e}"))?;
            let path = entry.path();
            let metadata = entry
                .metadata()
                .map_err(|e| format!("failed to read metadata {}: {e}", path.display()))?;
            if metadata.is_dir() {
                stack.push(path);
                continue;
            }
            if metadata.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }

    Ok(files)
}

fn scan_ownership_boundaries(root: &Path, now: DateTime<Utc>) -> Result<OwnershipBoundaryReport, String> {
    let contract_path = root.join("docs/architecture/tri_kernel_ownership_contract.md");
    let contract_src = std::fs::read_to_string(&contract_path)
        .map_err(|e| format!("failed to read contract file {contract_path:?}: {e}"))?;
    let contract = parse_frontmatter(&contract_src)?;

    let waiver_path = root.join(contract.waiver_policy.registry_path);
    let waiver_src = std::fs::read_to_string(&waiver_path)
        .map_err(|e| format!("failed to read waiver registry {waiver_path:?}: {e}"))?;
    let waiver_registry: WaiverRegistry =
        serde_json::from_str(&waiver_src).map_err(|e| format!("waiver registry parse failed: {e}"))?;

    let mut invalid_waivers = Vec::new();
    let mut expired_waivers = Vec::new();
    for waiver in &waiver_registry.waivers {
        if let Err(reason) = waiver_is_valid(waiver, now) {
            if reason.contains("expired") {
                expired_waivers.push(waiver.clone());
            } else {
                invalid_waivers.push(waiver.clone());
            }
        }
    }

    let mut modules_by_plane: BTreeMap<String, usize> = BTreeMap::new();
    let mut active_violations: Vec<BoundaryViolation> = Vec::new();
    let mut waived_violations: Vec<BoundaryViolation> = Vec::new();
    let mut modules_scanned = 0_usize;

    let src_root = root.join("crates/franken-node/src");
    let rust_files = collect_rust_files(&src_root)?;

    for entry in rust_files {
        let rel = entry
            .strip_prefix(&src_root)
            .map_err(|e| format!("failed to compute relative path: {e}"))?
            .to_string_lossy()
            .replace('\\', "/");

        let plane = classify_module(&rel);
        *modules_by_plane.entry(format!("{:?}", plane).to_ascii_lowercase()).or_insert(0) += 1;
        modules_scanned = modules_scanned.saturating_add(1);

        if plane != KernelPlane::Product {
            continue;
        }

        let src = std::fs::read_to_string(&entry)
            .map_err(|e| format!("failed to read module {}: {e}", entry.display()))?;

        for mut violation in detect_product_boundary_violations(&rel, &src) {
            if let Some(waiver) = waiver_registry
                .waivers
                .iter()
                .find(|w| w.file == violation.file && w.boundary == violation.boundary)
            {
                match waiver_is_valid(waiver, now) {
                    Ok(()) => {
                        violation.waived = true;
                        violation.event_code = OWN_003.to_string();
                        waived_violations.push(violation);
                    }
                    Err(_) => {
                        violation.event_code = OWN_004.to_string();
                        active_violations.push(violation);
                    }
                }
            } else {
                active_violations.push(violation);
            }
        }
    }

    let mut boundary_results = BTreeMap::new();
    boundary_results.insert(
        "product_to_correctness_internal".to_string(),
        if active_violations
            .iter()
            .any(|v| v.boundary == "product->correctness-internal")
        {
            "fail".to_string()
        } else {
            "pass".to_string()
        },
    );
    boundary_results.insert(
        "product_reimplements_execution_primitives".to_string(),
        if active_violations
            .iter()
            .any(|v| v.boundary == "product-reimplements-execution-primitive")
        {
            "fail".to_string()
        } else {
            "pass".to_string()
        },
    );

    // Contract surface assertions are part of scan result shape.
    if contract.schema_version.trim().is_empty()
        || contract.bead_id != "bd-1id0"
        || contract.section != "10.15"
        || contract.kernels.len() != 3
        || contract.hard_runtime_invariant_owners.len() != 10
        || contract.permitted_cross_kernel_interfaces.is_empty()
        || contract.structured_event_codes.len() < 4
    {
        return Err("contract frontmatter is incomplete".to_string());
    }

    Ok(OwnershipBoundaryReport {
        schema_version: "ownership-boundary-report-v1".to_string(),
        bead_id: "bd-1id0".to_string(),
        generated_on: now.to_rfc3339(),
        modules_scanned,
        modules_by_plane,
        boundary_results,
        active_violations,
        waived_violations,
        invalid_waivers,
        expired_waivers,
    })
}

fn write_artifacts(report: &OwnershipBoundaryReport, root: &Path) -> Result<(), String> {
    let report_path = root.join("artifacts/10.15/ownership_boundary_report.json");
    let evidence_path = root.join("artifacts/section_10_15/bd-1id0/verification_evidence.json");
    let summary_path = root.join("artifacts/section_10_15/bd-1id0/verification_summary.md");

    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create report parent {parent:?}: {e}"))?;
    }
    if let Some(parent) = evidence_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create evidence parent {parent:?}: {e}"))?;
    }
    if let Some(parent) = summary_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create summary parent {parent:?}: {e}"))?;
    }

    std::fs::write(
        &report_path,
        serde_json::to_string_pretty(report)
            .map_err(|e| format!("failed to serialize report: {e}"))?,
    )
    .map_err(|e| format!("failed to write report: {e}"))?;

    let status = if report.active_violations.is_empty()
        && report.invalid_waivers.is_empty()
        && report.expired_waivers.is_empty()
    {
        "pass"
    } else {
        "fail"
    };

    let evidence = VerificationEvidence {
        bead_id: "bd-1id0",
        gate: "ownership_boundary_checks",
        generated_on: report.generated_on.clone(),
        status,
        modules_scanned: report.modules_scanned,
        active_violations: report.active_violations.len(),
        waived_violations: report.waived_violations.len(),
        invalid_waivers: report.invalid_waivers.len(),
        expired_waivers: report.expired_waivers.len(),
    };
    std::fs::write(
        &evidence_path,
        serde_json::to_string_pretty(&evidence)
            .map_err(|e| format!("failed to serialize evidence: {e}"))?,
    )
    .map_err(|e| format!("failed to write evidence: {e}"))?;

    let mut summary = String::new();
    summary.push_str("# bd-1id0 Verification Summary\n\n");
    summary.push_str(&format!("- Status: **{}** ({})\n", status.to_uppercase(), OWN_001));
    summary.push_str(&format!("- Generated on: `{}`\n", report.generated_on));
    summary.push_str(&format!("- Modules scanned: `{}`\n", report.modules_scanned));
    summary.push_str(&format!("- Active violations ({}): `{}`\n", OWN_002, report.active_violations.len()));
    summary.push_str(&format!("- Waived violations ({}): `{}`\n", OWN_003, report.waived_violations.len()));
    summary.push_str(&format!("- Invalid/expired waivers ({}): `{}`\n", OWN_004, report.invalid_waivers.len() + report.expired_waivers.len()));
    std::fs::write(&summary_path, summary).map_err(|e| format!("failed to write summary: {e}"))?;

    Ok(())
}

#[test]
fn ownership_boundary_gate_has_no_unwaived_violations() {
    let root = repo_root();
    let now = Utc::now();

    let report = scan_ownership_boundaries(&root, now).expect("ownership scan should succeed");
    write_artifacts(&report, &root).expect("ownership artifacts should write");

    assert!(
        report.invalid_waivers.is_empty(),
        "{} invalid waiver entries found",
        OWN_004
    );
    assert!(
        report.expired_waivers.is_empty(),
        "{} expired waiver entries found",
        OWN_004
    );
    assert!(
        report.active_violations.is_empty(),
        "{} boundary violations found: {}",
        OWN_002,
        serde_json::to_string_pretty(&report.active_violations).expect("serialize")
    );
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn parse_frontmatter_requires_section_and_kernels() {
        let md = r#"---
schema_version: \"1.0\"
bead_id: \"bd-1id0\"
section: \"10.15\"
kernels:
  franken_engine:
    plane: execution
    owns: [\"runtime\"]
  asupersync:
    plane: correctness-control
    owns: [\"cancellation\"]
  franken_node:
    plane: product
    owns: [\"ux\"]
hard_runtime_invariant_owners:
  HRI-01: asupersync
  HRI-02: asupersync
  HRI-03: asupersync
  HRI-04: asupersync
  HRI-05: asupersync
  HRI-06: asupersync
  HRI-07: asupersync
  HRI-08: asupersync
  HRI-09: asupersync
  HRI-10: franken_node
permitted_cross_kernel_interfaces: [\"iface\"]
waiver_policy:
  registry_path: docs/governance/ownership_boundary_waivers.json
  required_fields: [waiver_id]
  expiry_enforced: true
  unsigned_allowed: false
structured_event_codes: [OWN-001, OWN-002, OWN-003, OWN-004]
---
# title
"#;
        let fm = parse_frontmatter(md).expect("frontmatter parse");
        assert_eq!(fm.section, "10.15");
        assert_eq!(fm.kernels.len(), 3);
        assert_eq!(fm.hard_runtime_invariant_owners.len(), 10);
        assert!(fm.structured_event_codes.contains(&OWN_001.to_string()));
    }

    #[test]
    fn waiver_validation_rejects_unsigned_or_expired() {
        let now = Utc::now();

        let unsigned = WaiverRecord {
            waiver_id: "W1".to_string(),
            file: "a.rs".to_string(),
            boundary: "product->correctness-internal".to_string(),
            rationale: "test".to_string(),
            signed_by: "".to_string(),
            signature: "".to_string(),
            expires_at: (now + chrono::Duration::days(1)).to_rfc3339(),
        };
        assert!(waiver_is_valid(&unsigned, now).is_err());

        let expired = WaiverRecord {
            waiver_id: "W2".to_string(),
            file: "a.rs".to_string(),
            boundary: "product->correctness-internal".to_string(),
            rationale: "test".to_string(),
            signed_by: "owner".to_string(),
            signature: "sig".to_string(),
            expires_at: (now - chrono::Duration::days(1)).to_rfc3339(),
        };
        assert!(waiver_is_valid(&expired, now).is_err());
    }

    #[test]
    fn synthetic_violation_detected() {
        let src = "use crate::control_plane::internal::thing;\n";
        let violations = detect_product_boundary_violations("api/example.rs", src);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].event_code, OWN_002);
        assert_eq!(violations[0].boundary, "product->correctness-internal");
    }
}
