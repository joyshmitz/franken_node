# Drift Report Schema

## Version

v1 (2026-02-20)

## Purpose

Documents the structured output format for transplant drift detection and re-sync reports. These reports are consumed by CI gates, operator dashboards, and downstream integrity workflows.

## Drift Detection Report (`drift_detect.sh --json`)

```json
{
  "verdict": "NO_DRIFT | DRIFT_DETECTED",
  "timestamp": "<ISO-8601 UTC>",
  "lockfile_entries": "<int>",
  "source_root": "<absolute path>",
  "snapshot_dir": "<directory name>",
  "findings": {
    "total": "<int>",
    "content_drift": "<int>",
    "missing_local": "<int>",
    "missing_source": "<int>",
    "extra_local": "<int>"
  },
  "details": {
    "content_drift": ["<relpath>", ...],
    "missing_local": ["<relpath>", ...],
    "missing_source": ["<relpath>", ...],
    "extra_local": ["<relpath>", ...]
  }
}
```

### Drift Categories

| Code | Stable ID | Description |
|------|-----------|-------------|
| CONTENT_DRIFT | `drift.content` | File exists in both snapshot and source but SHA-256 digests differ |
| MISSING_LOCAL | `drift.missing_local` | File listed in lockfile but not present in local snapshot |
| MISSING_SOURCE | `drift.missing_source` | File listed in lockfile but not present in upstream source |
| EXTRA_LOCAL | `drift.extra_local` | File present in local snapshot but not listed in lockfile |

### Verdicts

| Verdict | Exit Code | Meaning |
|---------|-----------|---------|
| `NO_DRIFT` | 0 | All lockfile entries match, no extras |
| `DRIFT_DETECTED` | 1 | One or more findings detected |

## Re-sync Report (`resync.sh --json`)

```json
{
  "verdict": "PASS | FAIL | DRY_RUN | NO_DRIFT",
  "timestamp": "<ISO-8601 UTC>",
  "source_root": "<absolute path>",
  "drift_before": { "<drift detection report>" },
  "actions_taken": "<int>",
  "verification_after": { "<lockfile verification report>" }
}
```

### Re-sync Verdicts

| Verdict | Exit Code | Meaning |
|---------|-----------|---------|
| `NO_DRIFT` | 0 | No re-sync needed |
| `DRY_RUN` | 0 | Preview mode, no files modified |
| `PASS` | 0 | Re-sync completed, verification passed |
| `FAIL` | 1 | Re-sync completed but verification failed |

## Trace Correlation

All reports include a `timestamp` field for correlation. For CI integration, pipe JSON through `jq` and key on `.verdict` for gating decisions.
