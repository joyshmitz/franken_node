# bd-1sgr: Report Output Contract — Verification Summary

**Section:** 16 | **Bead:** bd-1sgr | **Date:** 2026-02-20

## Gate Result: PASS (18/18)

All checks passed:
- Source exists and module wired in mod.rs
- 5 report types (TechnicalAnalysis, SecurityAssessment, PerformanceBenchmark, ComplianceReport, IncidentPostmortem)
- 5 required artifact types including report_pdf
- 4 required structs (ReportBundle, ArtifactEntry, OutputCatalog, ReportOutputContract)
- SHA-256 integrity verification via content_hash + Sha256
- Completeness checking with REQUIRED_ARTIFACT_TYPES
- Reproduction command support
- Catalog generation with OutputCatalog
- 12/12 event codes (ROC-001..ROC-010, ROC-ERR-001, ROC-ERR-002)
- 6/6 invariants (INV-ROC-COMPLETE/DETERMINISTIC/INTEGRITY/REPRODUCIBLE/VERSIONED/AUDITABLE)
- JSONL audit export with RocAuditRecord
- Contract version roc-v1.0
- Spec contract aligned
- Test coverage met

## Test Results
- **Gate script:** 18/18 PASS
- **Python tests:** 26/26 PASS
- **Rust tests:** 18+ in-module tests
