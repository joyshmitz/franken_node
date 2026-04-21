# Lane Scheduler Golden Artifacts Provenance

## Generation Method

These golden artifacts were generated from the `lane_scheduler_golden_artifacts.rs` test suite, which creates deterministic lane scheduler telemetry snapshots under controlled conditions.

## Generator Version

- **frankenengine-node version**: Current workspace version
- **Test harness**: `tests/lane_scheduler_golden_artifacts.rs`
- **Generation command**: `UPDATE_GOLDENS=1 cargo test lane_scheduler_golden`
- **Generated on**: 2026-04-21 (bd-20vg7 testing improvement)

## Test Scenarios Covered

1. **Minimal Scheduler** (`minimal_scheduler_snapshot.golden`)
   - Single lane (Background) with basic task admission/completion
   - Tests baseline telemetry format

2. **Multi-Lane Scheduler** (`multi_lane_scheduler_snapshot.golden`)
   - Three lanes: ControlCritical, RemoteEffect, Background
   - Multiple task types across lanes
   - Mixed completion states

3. **Capacity Enforcement** (`capacity_enforcement_snapshot.golden`)
   - Lane with capacity=1 to test cap enforcement
   - Failed admission due to capacity limits

4. **Epoch Boundary Conditions** (`epoch_boundary_snapshot.golden`)
   - Large epoch timestamp values (4000000000+)
   - Tests timestamp handling in snapshots

5. **Policy Configuration** (`multi_lane_policy_config.golden`)
   - Serialized multi-lane policy structure
   - Lane configurations and task mappings

6. **Validation Errors** (`policy_validation_errors.golden`)
   - Various invalid policy configurations
   - Error message format stability

7. **Audit Log Entries** (`scheduler_audit_log_entries.golden`)
   - Sequence of scheduler operations
   - Audit trail structure and metadata

8. **Starvation Detection** (`starvation_detection_snapshot.golden`)
   - Starvation window configuration and detection
   - Long-running task scenarios

## Dynamic Value Scrubbing

The following dynamic values are automatically scrubbed before golden comparison:

- **Timestamps**: Large integers (13+ digits) → `[TIMESTAMP]`
- **Nonces**: Random hex strings in nonce fields → `[NONCE]`
- **Task IDs**: Task/trace identifiers → `[TASK_ID]`
- **Session IDs**: Long hex session identifiers → `[SESSION_ID]`
- **Memory addresses**: 0x-prefixed hex addresses → `[ADDR]`
- **High-precision durations**: Microsecond/nanosecond values → `[DURATION]`
- **Thread IDs**: Numeric thread identifiers → `[THREAD_ID]`

## Regeneration Instructions

1. **Full regeneration**: 
   ```bash
   UPDATE_GOLDENS=1 cargo test lane_scheduler_golden
   ```

2. **Single test regeneration**:
   ```bash
   UPDATE_GOLDENS=1 cargo test golden_telemetry_snapshot_minimal_scheduler
   ```

3. **Review changes**:
   ```bash
   git diff tests/golden/lane_scheduler/
   ```

4. **Commit approved changes**:
   ```bash
   git add tests/golden/lane_scheduler/
   git commit -m "Update lane scheduler golden artifacts: [reason]"
   ```

## Integration with Existing Tests

These golden artifact tests complement the existing test suite:

- **`runtime_lane_scheduler_conformance.rs`**: Focuses on behavioral correctness and hardening patterns
- **`lane_scheduler_fuzz_harness.rs`**: Structure-aware fuzzing for policy variations
- **`lane_scheduler_golden_artifacts.rs`**: Output format stability validation

## Review Requirements

Every golden file change must be manually reviewed to ensure:

1. The change represents an intentional behavior modification
2. The scrubbed output format remains sensible and deterministic
3. No sensitive or dynamic values leaked through scrubbing
4. The structural integrity of telemetry snapshots is preserved

## CI Integration

Golden artifact tests run automatically in CI and will fail if any golden file differs from the expected output. Use `UPDATE_GOLDENS=1` only in development - never in CI.