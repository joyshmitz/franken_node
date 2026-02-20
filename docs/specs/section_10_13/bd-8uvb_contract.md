# bd-8uvb: Overlapping-Lease Conflict Policy

## Purpose

Detect and resolve overlapping lease conflicts via deterministic rules. Dangerous conflicts halt and alert. Fork handling logs contain reproducible evidence for triage.

## Invariants

- **INV-OLC-DETERMINISTIC**: Same conflict inputs → same resolution outcome.
- **INV-OLC-DANGEROUS-HALT**: Dangerous-tier conflicts always halt; never silently resolved.
- **INV-OLC-FORK-LOG**: Every conflict produces a ForkLogEntry with trace correlation.
- **INV-OLC-CLASSIFIED**: Every conflict failure tagged with a stable error code.

## Types

### ConflictPolicy

Holds overlap detection and resolution configuration.

### LeaseConflict

Describes an overlap: two lease IDs, the resource, the overlap window, and the safety tier.

### ConflictResolution

Resolution outcome: the winning lease, the loser, the rule applied, and whether the system halted.

### ForkLogEntry

Deterministic fork handling log entry with trace_id, action_id, timestamp, conflict details, and resolution.

### LeaseConflictDetector

Service that accepts active leases and detects pairwise overlaps on the same resource, then resolves via policy.

## Functions

- `detect_conflicts(leases, resource, now)` → `Vec<LeaseConflict>`
- `resolve_conflict(conflict, policy)` → `Result<ConflictResolution, ConflictError>`
- `fork_log_entry(conflict, resolution)` → `ForkLogEntry`

## Error Codes

- `OLC_DANGEROUS_HALT` — dangerous conflict requires halt
- `OLC_BOTH_ACTIVE` — two active leases on same resource
- `OLC_NO_WINNER` — policy cannot determine a winner
- `OLC_FORK_LOG_INCOMPLETE` — fork log entry missing required fields

## Resolution Rules

1. **Earliest grant wins**: the lease granted first takes precedence.
2. **Purpose priority**: MigrationHandoff > StateWrite > Operation.
3. **Dangerous tier**: if either lease is in a dangerous-tier context, halt immediately — do not resolve automatically.
