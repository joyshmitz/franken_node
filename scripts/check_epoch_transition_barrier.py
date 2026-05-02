#!/usr/bin/env python3
"""bd-2wsm: Epoch transition barrier protocol — verification gate."""
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "epoch_transition_barrier.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "control_plane" / "mod.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_14" / "bd-2wsm_contract.md"
BEAD, SECTION = "bd-2wsm", "10.14"

EVENT_CODES = [
    "BARRIER_PROPOSED", "BARRIER_DRAIN_ACK", "BARRIER_COMMITTED",
    "BARRIER_ABORTED", "BARRIER_TIMEOUT", "BARRIER_DRAIN_FAILED",
    "BARRIER_ABORT_SENT", "BARRIER_CONCURRENT_REJECTED",
    "BARRIER_TRANSCRIPT_EXPORTED", "BARRIER_PARTICIPANT_REGISTERED",
]
ERROR_CODES = [
    "ERR_BARRIER_CONCURRENT", "ERR_BARRIER_NO_PARTICIPANTS",
    "ERR_BARRIER_TIMEOUT", "ERR_BARRIER_DRAIN_FAILED",
    "ERR_BARRIER_ALREADY_COMPLETE", "ERR_BARRIER_INVALID_PHASE",
    "ERR_BARRIER_UNKNOWN_PARTICIPANT", "ERR_BARRIER_EPOCH_MISMATCH",
]
INVS = [
    "INV-BARRIER-ALL-ACK", "INV-BARRIER-NO-PARTIAL", "INV-BARRIER-ABORT-SAFE",
    "INV-BARRIER-SERIALIZED", "INV-BARRIER-TRANSCRIPT", "INV-BARRIER-TIMEOUT",
]

def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _checks() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    def ok(name: str, passed: bool, detail: str = "") -> None:
        results.append({"check": name, "passed": passed, "detail": detail})

    src = _read_text(IMPL) if IMPL.is_file() else ""
    mod_src = _read_text(MOD_RS) if MOD_RS.is_file() else ""

    # File existence and module wiring
    ok("source_exists", IMPL.is_file(), str(IMPL))
    ok("module_wiring", "pub mod epoch_transition_barrier;" in mod_src)

    # Core types
    for st in ["BarrierPhase", "DrainAck", "AbortReason", "BarrierError",
               "BarrierConfig", "TranscriptEntry", "BarrierTranscript",
               "BarrierAuditRecord", "BarrierInstance", "EpochTransitionBarrier"]:
        ok(f"struct_{st}", st in src and ("struct " + st in src or "enum " + st in src or "pub struct " + st in src), st)

    # Protocol phases
    ok("phase_proposed", "Proposed" in src, "Proposed phase")
    ok("phase_draining", "Draining" in src, "Draining phase")
    ok("phase_committed", "Committed" in src, "Committed phase")
    ok("phase_aborted", "Aborted" in src, "Aborted phase")

    # Core operations
    ok("fn_propose", "fn propose" in src, "Propose barrier")
    ok("fn_record_drain_ack", "fn record_drain_ack" in src, "Record drain ACK")
    ok("fn_try_commit", "fn try_commit" in src, "Try commit")
    ok("fn_abort", "fn abort" in src, "Abort barrier")
    ok("fn_record_drain_failure", "fn record_drain_failure" in src, "Record drain failure")
    ok("fn_check_participant_timeouts", "fn check_participant_timeouts" in src, "Check participant timeouts")
    ok("fn_register_participant", "fn register_participant" in src, "Register participant")

    # Barrier features
    ok("all_acked", "fn all_acked" in src, "All-ACK check")
    ok("missing_acks", "fn missing_acks" in src, "Missing ACKs tracking")
    ok("is_terminal", "fn is_terminal" in src, "Terminal state detection")
    ok("is_barrier_active", "fn is_barrier_active" in src, "Active barrier check")
    ok("configurable_timeout", "drain_timeout_for" in src and "participant_timeouts" in src, "Configurable per-participant timeout")

    # Transcript and audit
    ok("transcript_export", "fn export_jsonl" in src, "JSONL transcript export")
    ok("audit_log", "fn export_audit_log_jsonl" in src, "JSONL audit log export")

    # Event codes
    ec = sum(1 for c in EVENT_CODES if c in src)
    ok("event_codes", ec >= 8, f"{ec}/10")

    # Error codes
    erc = sum(1 for c in ERROR_CODES if c in src)
    ok("error_codes", erc >= 8, f"{erc}/8")

    # Invariants
    inv = sum(1 for i in INVS if i in src)
    ok("invariants", inv >= 6, f"{inv}/6")

    # Config validation
    ok("config_validation", "fn validate" in src, "Config validation")

    # Schema version
    ok("schema_version", "eb-v1.0" in src, "eb-v1.0")

    # Spec alignment
    ok("spec_alignment", SPEC.is_file(), str(SPEC))

    # Test coverage
    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage", test_count >= 25, f"{test_count} tests")

    return results


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def self_test() -> bool:
    results = _checks()
    _require(len(results) >= 25, "too few checks")
    for check in results:
        _require("check" in check and "passed" in check, "malformed check result")
    print(f"self_test: {len(results)} checks OK", file=sys.stderr)
    return True


def main() -> int:
    configure_test_logging("check_epoch_transition_barrier")
    as_json = "--json" in sys.argv
    if "--self-test" in sys.argv:
        self_test()
        return 0
    results = _checks()
    p = sum(1 for x in results if x["passed"])
    t = len(results)
    v = "PASS" if p == t else "FAIL"
    if as_json:
        print(
            json.dumps(
                {
                    "bead_id": BEAD,
                    "section": SECTION,
                    "gate_script": Path(__file__).name,
                    "checks_passed": p,
                    "checks_total": t,
                    "verdict": v,
                    "checks": results,
                },
                indent=2,
            )
        )
    else:
        for x in results:
            print(f"  [{'PASS' if x['passed'] else 'FAIL'}] {x['check']}: {x['detail']}")
        print(f"\n{BEAD}: {p}/{t} checks — {v}")
    return 0 if v == "PASS" else 1

if __name__ == "__main__":
    sys.exit(main())
