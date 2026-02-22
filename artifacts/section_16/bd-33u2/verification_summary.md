# bd-33u2: Widely Used Verifier/Benchmark Releases — Verification Summary

**Section:** 16 | **Bead:** bd-33u2 | **Date:** 2026-02-20

## Gate Result: PASS (19/19)

All checks passed:
- Source exists and module wired in mod.rs
- 5 release types (VerifierTool, BenchmarkSuite, TestHarness, ComplianceChecker, DocumentationKit)
- 4 release statuses (Draft, Published, Deprecated, Archived)
- 5 required structs (ToolRelease, ReleaseArtifact, DownloadRecord, AdoptionMetrics, VerifierBenchmarkReleases)
- Download tracking with count
- Quality-gated publication with MIN_QUALITY_SCORE
- Changelog management
- SHA-256 content hashing
- 12/12 event codes (VBR-001..VBR-010, VBR-ERR-001, VBR-ERR-002)
- 6/6 invariants (INV-VBR-TYPED/TRACKED/DETERMINISTIC/GATED/VERSIONED/AUDITABLE)
- JSONL audit export with VbrAuditRecord
- Schema version vbr-v1.0
- 22 Rust in-module tests

## Test Results
- **Gate script:** 19/19 PASS
- **Python tests:** 27/27 PASS
