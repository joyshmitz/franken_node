#!/usr/bin/env python3
"""Generate the lifecycle transition matrix JSON artifact."""

import json
from pathlib import Path

STATES = [
    "discovered", "verified", "installed", "configured",
    "active", "paused", "stopped", "failed",
]

LEGAL_TRANSITIONS = {
    ("discovered", "verified"),
    ("discovered", "failed"),
    ("verified", "installed"),
    ("verified", "failed"),
    ("installed", "configured"),
    ("installed", "failed"),
    ("configured", "active"),
    ("configured", "failed"),
    ("active", "paused"),
    ("active", "stopped"),
    ("active", "failed"),
    ("paused", "active"),
    ("paused", "stopped"),
    ("paused", "failed"),
    ("stopped", "configured"),
    ("stopped", "failed"),
    ("failed", "discovered"),
}

ROOT = Path(__file__).resolve().parent.parent
out_dir = ROOT / "artifacts" / "section_10_13" / "bd-2gh"
out_dir.mkdir(parents=True, exist_ok=True)

transitions = []
for s in STATES:
    for t in STATES:
        if s == t:
            continue
        transitions.append({
            "from": s,
            "to": t,
            "legal": (s, t) in LEGAL_TRANSITIONS,
        })

data = {
    "schema": "connector_lifecycle_transition_matrix",
    "version": "1.0",
    "states": STATES,
    "total_transitions": len(transitions),
    "legal_count": sum(1 for e in transitions if e["legal"]),
    "illegal_count": sum(1 for e in transitions if not e["legal"]),
    "transitions": transitions,
}

path = out_dir / "lifecycle_transition_matrix.json"
path.write_text(json.dumps(data, indent=2))
print(f"Written {path}")
