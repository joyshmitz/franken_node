#!/usr/bin/env python3
"""bd-n1w: Verification script for frontier demo gates with external reproducibility.

Usage:
    python3 scripts/check_frontier_demo_gates.py           # human-readable
    python3 scripts/check_frontier_demo_gates.py --json     # machine-readable
    python3 scripts/check_frontier_demo_gates.py --self-test # internal consistency
"""

import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone
from pathlib import Path


# -- File paths ----------------------------------------------------------------

IMPL_FILE = ROOT / "crates/franken-node/src/tools/frontier_demo_gate.rs"
MOD_FILE = ROOT / "crates/franken-node/src/tools/mod.rs"
SPEC_FILE = ROOT / "docs/specs/section_10_12/bd-n1w_contract.md"
MANIFEST_FILE = ROOT / "artifacts/10.12/frontier_demo_manifest.json"
TEST_FILE = ROOT / "tests/test_check_frontier_demo_gates.py"
EVIDENCE_FILE = ROOT / "artifacts/section_10_12/bd-n1w/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_12/bd-n1w/verification_summary.md"

# -- Required elements ---------------------------------------------------------

REQUIRED_FRONTIER_PROGRAMS = [
    "MigrationSingularity",
    "TrustFabric",
    "VerifierEconomy",
    "OperatorIntelligence",
    "EcosystemNetworkEffects",
]

REQUIRED_FRONTIER_LABELS = [
    "migration_singularity",
    "trust_fabric",
    "verifier_economy",
    "operator_intelligence",
    "ecosystem_network_effects",
]

REQUIRED_STRUCTS = [
    "DemoGateResult",
    "ResourceMetrics",
    "ReproducibilityManifest",
    "ExternalVerifierBootstrap",
    "DemoGateRunner",
    "DemoEvent",
    "DefaultDemoGate",
]

REQUIRED_TRAIT_METHODS = [
    "fn input_corpus(",
    "fn execute(",
    "fn output_schema(",
    "fn attestation(",
]

REQUIRED_EVENT_CODES = [
    "DEMO_GATE_START",
    "DEMO_GATE_PASS",
    "DEMO_GATE_FAIL",
    "MANIFEST_GENERATED",
    "EXTERNAL_VERIFY_START",
    "EXTERNAL_VERIFY_MATCH",
    "EXTERNAL_VERIFY_MISMATCH",
]

REQUIRED_ERROR_CODES = [
    "ERR_DEMO_GATE_NOT_FOUND",
    "ERR_DEMO_EXECUTION_FAILED",
    "ERR_DEMO_FINGERPRINT_MISMATCH",
    "ERR_DEMO_MANIFEST_INVALID",
    "ERR_DEMO_BOOTSTRAP_FAILED",
    "ERR_DEMO_ISOLATION_VIOLATED",
    "ERR_DEMO_SCHEMA_MISMATCH",
]

REQUIRED_INVARIANTS = [
    "INV_DEMO_DETERMINISTIC",
    "INV_DEMO_ISOLATED",
    "INV_DEMO_FINGERPRINTED",
    "INV_DEMO_REPRODUCIBLE",
    "INV_DEMO_MANIFEST_COMPLETE",
    "INV_DEMO_SCHEMA_VERSIONED",
]

# -- Helpers -------------------------------------------------------------------


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "passed": ok, "detail": detail or ("ok" if ok else "FAIL")}


# -- Check functions -----------------------------------------------------------


def _checks() -> list:
    """Return list of {check, passed, detail} dicts."""
    checks = []
    src = _read(IMPL_FILE)
    mod_src = _read(MOD_FILE)

    # 1. Rust module exists
    checks.append(_check(
        "Rust module exists",
        IMPL_FILE.exists(),
        str(IMPL_FILE),
    ))

    # 2. Wired into tools/mod.rs
    checks.append(_check(
        "Wired into tools/mod.rs",
        "pub mod frontier_demo_gate;" in mod_src,
        "frontier_demo_gate in mod.rs",
    ))

    # 3. Spec contract exists
    checks.append(_check(
        "Spec contract exists",
        SPEC_FILE.exists(),
        str(SPEC_FILE),
    ))

    # 4. Demo manifest artifact exists
    checks.append(_check(
        "Demo manifest artifact exists",
        MANIFEST_FILE.exists(),
        str(MANIFEST_FILE),
    ))

    # 5. Test file exists
    checks.append(_check(
        "Test file exists",
        TEST_FILE.exists(),
        str(TEST_FILE),
    ))

    # 6. Evidence exists with PASS verdict
    evidence_pass = False
    if EVIDENCE_FILE.exists():
        try:
            ev = json.loads(EVIDENCE_FILE.read_text(encoding="utf-8"))
            evidence_pass = ev.get("verdict") == "PASS"
        except (json.JSONDecodeError, OSError):
            pass
    checks.append(_check(
        "Evidence exists with PASS verdict",
        evidence_pass,
        str(EVIDENCE_FILE),
    ))

    # 7. Summary file exists
    checks.append(_check(
        "Verification summary exists",
        SUMMARY_FILE.exists(),
        str(SUMMARY_FILE),
    ))

    # 8. FrontierDemoGate trait defined
    checks.append(_check(
        "FrontierDemoGate trait defined",
        "pub trait FrontierDemoGate" in src,
    ))

    # 9. DemoGateRunner struct defined
    checks.append(_check(
        "DemoGateRunner struct defined",
        "pub struct DemoGateRunner" in src,
    ))

    # 10. ReproducibilityManifest struct defined
    checks.append(_check(
        "ReproducibilityManifest struct defined",
        "pub struct ReproducibilityManifest" in src,
    ))

    # 11. FrontierProgram enum defined
    checks.append(_check(
        "FrontierProgram enum defined",
        "pub enum FrontierProgram" in src,
    ))

    # 12-16. Five frontier program variants
    for variant in REQUIRED_FRONTIER_PROGRAMS:
        checks.append(_check(
            f"FrontierProgram::{variant} variant defined",
            variant in src,
        ))

    # 17. DemoGateResult struct defined
    checks.append(_check(
        "DemoGateResult struct defined",
        "pub struct DemoGateResult" in src,
    ))

    # 18. ExternalVerifierBootstrap struct defined
    checks.append(_check(
        "ExternalVerifierBootstrap struct defined",
        "pub struct ExternalVerifierBootstrap" in src,
    ))

    # 19-22. Trait methods defined
    for method in REQUIRED_TRAIT_METHODS:
        checks.append(_check(
            f"Trait method '{method.strip()}' defined",
            method in src,
        ))

    # 23-29. Event codes defined
    for code in REQUIRED_EVENT_CODES:
        checks.append(_check(
            f"Event code {code} defined",
            code in src,
        ))

    # 30-36. Error codes defined
    for code in REQUIRED_ERROR_CODES:
        checks.append(_check(
            f"Error code {code} defined",
            code in src,
        ))

    # 37-42. Invariants defined
    for inv in REQUIRED_INVARIANTS:
        checks.append(_check(
            f"Invariant {inv} defined",
            inv in src,
        ))

    # 43. Schema version demo-v1.0
    checks.append(_check(
        "Schema version demo-v1.0",
        'demo-v1.0' in src,
    ))

    # 44. BTreeMap usage for determinism
    checks.append(_check(
        "BTreeMap usage for determinism",
        "BTreeMap" in src,
    ))

    # 45. Serde derives
    checks.append(_check(
        "Serialize/Deserialize derives",
        "Serialize" in src and "Deserialize" in src,
    ))

    # 46. Tests present (>= 40)
    test_count = src.count("#[test]")
    checks.append(_check(
        f"Rust unit tests ({test_count} >= 40)",
        test_count >= 40,
        f"{test_count} tests found",
    ))

    # 47. Required structs defined
    for s in REQUIRED_STRUCTS:
        found = f"pub struct {s}" in src
        checks.append(_check(f"Struct {s} defined", found))

    # 48. Manifest artifact has all 5 programs
    manifest_has_programs = False
    if MANIFEST_FILE.exists():
        try:
            mf = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
            programs = mf.get("programs", [])
            prog_names = [p.get("name", "") for p in programs]
            manifest_has_programs = all(
                label in prog_names for label in REQUIRED_FRONTIER_LABELS
            )
        except (json.JSONDecodeError, OSError):
            pass
    checks.append(_check(
        "Manifest contains all 5 frontier programs",
        manifest_has_programs,
    ))

    # 49. Manifest has manifest_fingerprint field
    manifest_has_fp = False
    if MANIFEST_FILE.exists():
        try:
            mf = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
            manifest_has_fp = "manifest_fingerprint" in mf
        except (json.JSONDecodeError, OSError):
            pass
    checks.append(_check(
        "Manifest has manifest_fingerprint field",
        manifest_has_fp,
    ))

    # 50. Manifest has git_commit_hash field
    manifest_has_git = False
    if MANIFEST_FILE.exists():
        try:
            mf = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
            manifest_has_git = "git_commit_hash" in mf
        except (json.JSONDecodeError, OSError):
            pass
    checks.append(_check(
        "Manifest has git_commit_hash field",
        manifest_has_git,
    ))

    # 51. Manifest has timing data
    manifest_has_timing = False
    if MANIFEST_FILE.exists():
        try:
            mf = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
            manifest_has_timing = "timing" in mf
        except (json.JSONDecodeError, OSError):
            pass
    checks.append(_check(
        "Manifest has timing data",
        manifest_has_timing,
    ))

    # 52. Manifest has environment field
    manifest_has_env = False
    if MANIFEST_FILE.exists():
        try:
            mf = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
            manifest_has_env = "environment" in mf
        except (json.JSONDecodeError, OSError):
            pass
    checks.append(_check(
        "Manifest has environment field",
        manifest_has_env,
    ))

    # 53. event_codes module defined
    checks.append(_check(
        "event_codes module defined",
        "pub mod event_codes" in src,
    ))

    # 54. error_codes module defined
    checks.append(_check(
        "error_codes module defined",
        "pub mod error_codes" in src,
    ))

    # 55. invariants module defined
    checks.append(_check(
        "invariants module defined",
        "pub mod invariants" in src,
    ))

    return checks


def self_test() -> dict:
    """Internal consistency checks for the gate script itself."""
    checks = []

    # Constants
    checks.append(_check("REQUIRED_FRONTIER_PROGRAMS == 5", len(REQUIRED_FRONTIER_PROGRAMS) == 5))
    checks.append(_check("REQUIRED_FRONTIER_LABELS == 5", len(REQUIRED_FRONTIER_LABELS) == 5))
    checks.append(_check("REQUIRED_STRUCTS >= 7", len(REQUIRED_STRUCTS) >= 7))
    checks.append(_check("REQUIRED_TRAIT_METHODS == 4", len(REQUIRED_TRAIT_METHODS) == 4))
    checks.append(_check("REQUIRED_EVENT_CODES == 7", len(REQUIRED_EVENT_CODES) == 7))
    checks.append(_check("REQUIRED_ERROR_CODES == 7", len(REQUIRED_ERROR_CODES) == 7))
    checks.append(_check("REQUIRED_INVARIANTS >= 5", len(REQUIRED_INVARIANTS) >= 5))

    # _checks returns list
    result = _checks()
    checks.append(_check("_checks returns list", isinstance(result, list)))
    checks.append(_check("_checks returns dicts", all(isinstance(c, dict) for c in result)))
    checks.append(_check("_checks >= 50 checks", len(result) >= 50))

    # Check structure
    for c in result[:5]:
        checks.append(_check(
            f"check '{c['check']}' has required keys",
            all(k in c for k in ["check", "passed", "detail"]),
        ))

    # Full run
    full = run_all()
    checks.append(_check("run_all has bead_id", full.get("bead_id") == "bd-n1w"))
    checks.append(_check("run_all has section", full.get("section") == "10.12"))
    checks.append(_check("run_all has verdict", full.get("verdict") in ("PASS", "FAIL")))
    checks.append(_check("run_all has events", isinstance(full.get("events"), list)))
    checks.append(_check("run_all has summary", isinstance(full.get("summary"), str)))
    checks.append(_check("run_all has timestamp", isinstance(full.get("timestamp"), str)))
    checks.append(_check("run_all has name", isinstance(full.get("name"), str)))

    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])
    verdict = "PASS" if failed == 0 else "FAIL"

    return {
        "name": "check_frontier_demo_gates self-test",
        "bead": "bd-n1w",
        "section": "10.12",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "events": [{"code": code, "status": "defined"} for code in REQUIRED_EVENT_CODES],
        "summary": f"Self-test: {passed}/{len(checks)} {verdict}",
    }


def run_all() -> dict:
    """Run all checks and return structured result."""
    checks = _checks()
    passed = sum(1 for c in checks if c["passed"])
    failed = sum(1 for c in checks if not c["passed"])
    verdict = "PASS" if failed == 0 else "FAIL"

    events = []
    for code in REQUIRED_EVENT_CODES:
        events.append({"code": code, "status": "defined"})

    summary_lines = [
        "bd-n1w: Frontier Demo Gates with External Reproducibility",
        f"Checks: {passed}/{len(checks)} passing",
        f"Verdict: {verdict}",
    ]
    if failed > 0:
        failing = [c for c in checks if not c["passed"]]
        for c in failing[:5]:
            summary_lines.append(f"  FAIL: {c['check']}: {c['detail']}")

    return {
        "name": "Frontier Demo Gates with External Reproducibility",
        "bead_id": "bd-n1w",
        "title": "Frontier Demo Gates with External Reproducibility Requirements",
        "section": "10.12",
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "events": events,
        "summary": "\n".join(summary_lines),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# -- CLI -----------------------------------------------------------------------


def main():
    logger = configure_test_logging("check_frontier_demo_gates")
    if "--self-test" in sys.argv:
        result = self_test()
        for c in result["checks"]:
            status = "PASS" if c["passed"] else "FAIL"
            print(f"  [{status}] {c['check']}")
        print(f"\nself-test: {result['passed']}/{result['total']} {result['verdict']}")
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"# {result['bead_id']}: {result['title']}")
        print(f"Section: {result['section']} | Verdict: {result['verdict']}")
        print(f"Checks: {result['passed']}/{result['total']} passing\n")
        for c in result["checks"]:
            status = "PASS" if c["passed"] else "FAIL"
            print(f"  [{status}] {c['check']}: {c['detail']}")
        if result["failed"] > 0:
            print(f"\n{result['failed']} check(s) failed.")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
