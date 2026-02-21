# Expected-Loss Model Policy

**Applies to:** All evidence contracts in sections 10-13 that influence release gates, policy changes, or capability grants.

## Purpose

This policy mandates that every decision-bearing contract explicitly quantify the expected loss of the proposed change. This replaces implicit risk acceptance with auditable, numeric risk assessment.

## Contract Requirements

### Mandatory Fields

Every contract must include an `expected_loss` section containing:

1. **Scenarios** (minimum 2): Each scenario specifies:
   - A human-readable label (e.g., "best_case", "worst_case", "moderate")
   - Probability of occurrence (numeric, strictly between 0 and 1 inclusive of 1)
   - Impact in concrete, measurable units from the standardized vocabulary
   - Computed expected loss (probability multiplied by impact value)
   - Data source citation (historical metrics, benchmarks, threat models)

2. **Aggregate expected loss**: The weighted mean across all scenarios.

3. **EV cross-reference**: Link to the EV score contract (bd-1jmq) for benefit comparison.

### Validation

- Probability must be numeric and in range (0, 1].
- Impact value must be a positive finite number.
- Expected loss must equal probability times impact value within 0.01 tolerance.
- At least two scenarios must be present with distinct labels.
- Every data source must be a non-empty string referencing verifiable evidence.

### EV Benefit Comparison

When the aggregate expected loss exceeds the EV benefit score:
- The contract must set `justification_required: true`.
- A `justification` text field must explain why the change is still warranted.
- The justification is reviewed during the approval workflow.

## Impact Unit Vocabulary

All impact values must use standardized units for cross-contract comparison:

| Unit | Description |
|------|-------------|
| `ms_p99_latency` | Tail latency increase in milliseconds |
| `error_rate_pct` | Error rate increase as percentage points |
| `incidents_per_month` | Expected additional incidents per month |
| `mttr_minutes` | Mean-time-to-recovery increase in minutes |
| `downtime_minutes_per_month` | Expected downtime minutes per month |
| `data_loss_records` | Expected records lost per incident |

## CI Enforcement

1. **Release gate**: Contracts missing expected_loss sections are rejected.
2. **Numeric validation**: Non-numeric or out-of-range values cause build failure.
3. **Arithmetic check**: Probability * impact != expected_loss triggers a warning.
4. **EV comparison**: Unjustified high-loss contracts are blocked.

## Event Codes

| Code | Trigger | Action |
|------|---------|--------|
| ELM-001 | Missing expected_loss section | Block release |
| ELM-002 | Invalid numeric values | Block release |
| ELM-003 | Arithmetic mismatch | Warn, require review |
| ELM-004 | High loss without justification | Block release |

## Governance

- Policy owner: Section 11 lead.
- Changes require review by at least one other section lead.
- Annual audit of aggregate expected loss across all contracts.
- Scenarios must be updated when new incident data becomes available.
