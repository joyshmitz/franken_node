#!/usr/bin/env python3
"""
Duplicate-implementation CI gate for franken_node.

Reads the canonical capability ownership registry and scans implementation
files to detect prohibited semantic redefinitions — i.e., when a non-canonical
track re-implements logic that belongs to a different track's canonical domain.

Usage:
    python3 scripts/check_ownership_violations.py [--json] [--waiver FILE]

Exit codes:
    0 = PASS (no violations)
    1 = FAIL (violations detected)
    2 = ERROR (registry missing, parse error)
"""

import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path

REGISTRY_PATH = ROOT / "docs" / "capability_ownership_registry.json"

# Track-to-directory mapping: which directories belong to which section.
# As the codebase grows, this mapping will expand.
# For now, map known ownership domains to file path patterns.
TRACK_PATH_PATTERNS = {
    "10.13": [
        "crates/*/src/fcp_*",
        "crates/*/src/revocation*",
        "crates/*/src/control_channel*",
        "crates/*/src/error_taxonomy*",
        "crates/*/src/auth_channel*",
    ],
    "10.14": [
        "crates/*/src/evidence_*",
        "crates/*/src/epoch_*",
        "crates/*/src/remote_registry*",
        "crates/*/src/idempotency*",
        "crates/*/src/saga_*",
        "crates/*/src/fault_harness*",
        "crates/*/src/dpor*",
        "crates/*/src/marker_stream*",
    ],
    "10.15": [
        "crates/*/src/asupersync_*",
        "crates/*/src/control_plane*",
    ],
    "10.17": [
        "crates/*/src/verifier_*",
        "crates/*/src/replay_capsule*",
        "crates/*/src/claim_compiler*",
        "crates/*/src/trust_scoreboard*",
        "crates/*/src/oracle_l2*",
    ],
    "10.18": [
        "crates/*/src/vef_*",
        "crates/*/src/policy_constraint_compiler*",
        "crates/*/src/receipt_commitment*",
        "crates/*/src/proof_gen*",
    ],
    "10.19": [
        "crates/*/src/atc_*",
        "crates/*/src/federated_signal*",
        "crates/*/src/global_prior*",
    ],
    "10.20": [
        "crates/*/src/dgis_*",
        "crates/*/src/topo_risk*",
        "crates/*/src/contagion_sim*",
    ],
    "10.21": [
        "crates/*/src/bpet_*",
        "crates/*/src/phenotype_*",
        "crates/*/src/drift_detect*",
        "crates/*/src/hazard_score*",
    ],
    "10.2": [
        "crates/*/src/compat_*",
        "crates/*/src/divergence_*",
        "crates/*/src/oracle_l1*",
        "crates/*/src/fixture_oracle*",
    ],
}

# Semantic keyword patterns that indicate implementation (not just integration/reference)
IMPLEMENTATION_INDICATORS = [
    r"^pub\s+(struct|enum|trait|fn|impl)\s+",
    r"^pub\s+async\s+fn\s+",
    r"^pub\s+mod\s+",
    r"^impl\s+",
]


def load_registry() -> dict:
    """Load and validate the capability ownership registry."""
    if not REGISTRY_PATH.exists():
        print(f"ERROR: Registry not found: {REGISTRY_PATH}", file=sys.stderr)
        sys.exit(2)
    with open(REGISTRY_PATH) as f:
        return json.load(f)


def load_waivers(waiver_path: str | None) -> list[dict]:
    """Load waiver file if provided."""
    if not waiver_path:
        return []
    path = Path(waiver_path)
    if not path.exists():
        return []
    with open(path) as f:
        data = json.load(f)
    return data.get("waivers", [])


def check_file_ownership(filepath: Path, registry: dict) -> list[dict]:
    """Check a single file for ownership violations."""
    violations = []
    relpath = str(filepath.relative_to(ROOT))

    # Determine which track this file belongs to based on path patterns
    file_track = None
    for track, patterns in TRACK_PATH_PATTERNS.items():
        for pattern in patterns:
            # Simple glob matching
            pattern_re = pattern.replace("*", "[^/]+")
            if re.match(pattern_re, relpath):
                file_track = track
                break
        if file_track:
            break

    if not file_track:
        return []  # File doesn't match any known track pattern

    # Check if this file implements capabilities owned by another track
    for cap in registry.get("capabilities", []):
        cap_owner = cap["canonical_owner"]
        owners = cap_owner.split("+")

        # Skip if this file's track is the canonical owner
        if file_track in owners:
            continue

        # Skip if this file's track is listed as an integration track
        if file_track in cap.get("integration_tracks", []):
            continue

        # Check if this file contains implementation patterns related to this capability
        # For now, check if the filename contains domain keywords
        domain = cap["domain"].lower()
        domain_keywords = [
            w for w in re.split(r"[,/+\s]+", domain)
            if len(w) > 3 and w not in ("and", "the", "with", "for")
        ]

        file_stem = filepath.stem.lower()
        matching_keywords = [kw for kw in domain_keywords if kw in file_stem]

        if matching_keywords:
            violations.append({
                "rule_id": f"OWNERSHIP-{cap['id']}",
                "file": relpath,
                "file_track": file_track,
                "capability": cap["id"],
                "capability_domain": cap["domain"],
                "canonical_owner": cap_owner,
                "matching_keywords": matching_keywords,
                "severity": "error",
                "remediation": (
                    f"File {relpath} (track {file_track}) appears to implement "
                    f"capability {cap['id']} which is canonically owned by track "
                    f"{cap_owner}. Move implementation to the canonical track or "
                    f"refactor to integration/adoption role."
                ),
            })

    return violations


def main():
    logger = configure_test_logging("check_ownership_violations")
    json_output = "--json" in sys.argv
    waiver_path = None
    for i, arg in enumerate(sys.argv):
        if arg == "--waiver" and i + 1 < len(sys.argv):
            waiver_path = sys.argv[i + 1]

    registry = load_registry()
    waivers = load_waivers(waiver_path)
    waiver_rules = {(w["file"], w["rule_id"]) for w in waivers}

    all_violations = []

    # Scan all Rust source files
    for rs_file in ROOT.rglob("crates/*/src/**/*.rs"):
        violations = check_file_ownership(rs_file, registry)
        for v in violations:
            # Check waivers
            if (v["file"], v["rule_id"]) in waiver_rules:
                v["waived"] = True
            else:
                v["waived"] = False
            all_violations.append(v)

    active_violations = [v for v in all_violations if not v["waived"]]
    waived_violations = [v for v in all_violations if v["waived"]]

    verdict = "PASS" if not active_violations else "FAIL"

    report = {
        "verdict": verdict,
        "timestamp": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
        "registry_capabilities": len(registry.get("capabilities", [])),
        "files_scanned": sum(
            1 for _ in ROOT.rglob("crates/*/src/**/*.rs")
        ),
        "active_violations": len(active_violations),
        "waived_violations": len(waived_violations),
        "violations": active_violations,
        "waived": waived_violations,
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Duplicate-Implementation CI Gate ===")
        print(f"Registry: {len(registry.get('capabilities', []))} capabilities")
        print(f"Files scanned: {report['files_scanned']}")
        print(f"Active violations: {len(active_violations)}")
        print(f"Waived violations: {len(waived_violations)}")
        print(f"Verdict: {verdict}")
        if active_violations:
            print()
            for v in active_violations:
                print(f"  [{v['rule_id']}] {v['file']}")
                print(f"    Track {v['file_track']} implements {v['capability']} "
                      f"(owned by {v['canonical_owner']})")
                print(f"    Remediation: {v['remediation']}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
