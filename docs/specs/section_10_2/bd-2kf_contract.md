# bd-2kf: Compatibility Mode Selection Policy

## Decision Rationale

The canonical plan (Section 10.2) requires a formal policy for the three compatibility modes (strict, balanced, legacy-risky) that govern how divergences are handled per band. The mode selection policy defines the default, the configuration interface, and enforcement rules.

## Mode Definitions

| Mode | Default? | Description |
|------|----------|-------------|
| `strict` | No | Maximum fidelity; errors on core + high-value divergences |
| `balanced` | Yes | Production default; errors on core, warns on high-value |
| `legacy-risky` | No | Permits unsafe behaviors behind explicit policy gates |

## Invariants

1. `docs/COMPATIBILITY_MODE_POLICY.md` exists with all 3 modes.
2. Default mode is `balanced`.
3. Each mode specifies behavior for all 4 bands.
4. `legacy-risky` mode documents the explicit opt-in requirement for unsafe behaviors.
5. Configuration format documented (TOML).
6. Policy references COMPATIBILITY_BANDS.md.

## Failure Semantics

- Missing policy document: FAIL
- Missing mode definition: FAIL per mode
- Missing default designation: FAIL
- Incomplete band coverage in any mode: FAIL
