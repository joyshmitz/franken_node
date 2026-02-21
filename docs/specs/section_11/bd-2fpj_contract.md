# bd-2fpj Contract: Expected-Loss Model

## Purpose

Define a mandatory, machine-verifiable contract field named
`change_summary.expected_loss_model` for subsystem change proposals.

This field quantifies the financial and operational loss expected from
subsystem failure or regression using a scenario-based expected-loss
calculation. Each proposal must enumerate at least three plausible
failure scenarios, assign probabilities and impact values, and compute
an aggregate expected loss that maps to a canonical loss category.

## Section

11 — Evidence and Decision Contracts

## Predecessor

bd-1jmq — EV score and tier contract field.

## Contract Field

Path:
- `change_summary.expected_loss_model`

Required sub-fields:

1. `scenarios` (list of objects, minimum 3) — each scenario contains:
   - `name` (non-empty string) — human-readable scenario identifier
   - `probability` (float in [0.0, 1.0]) — estimated probability of occurrence
   - `impact_value` (float, non-negative) — quantified impact magnitude
   - `impact_unit` (string in `{dollars, hours, severity_units}`) — unit of impact measurement
   - `mitigation` (non-empty string) — planned mitigation strategy

2. `aggregate_expected_loss` (float, non-negative) — computed as:
   ```
   aggregate_expected_loss = sum(scenario.probability * scenario.impact_value for scenario in scenarios)
   ```

3. `confidence_interval` (object) — statistical confidence bounds:
   - `lower` (float, non-negative) — lower bound of expected loss
   - `upper` (float, non-negative) — upper bound of expected loss
   - `confidence_level` (float in (0.0, 1.0)) — e.g. 0.95 for 95% CI

4. `loss_category` (string in `{negligible, minor, moderate, major, catastrophic}`) — categorical classification based on aggregate expected loss thresholds.

### Expected Loss Formula

```
Expected Loss = sum(P(scenario_i) * Impact(scenario_i)) for all i in scenarios
```

Where:
- P(scenario_i) is the probability of scenario i, a float in [0.0, 1.0]
- Impact(scenario_i) is the quantified impact value (dollars, hours, or severity units)

### Loss Category Thresholds

| Category | Aggregate Expected Loss Range | Description |
|----------|-------------------------------|-------------|
| negligible | < 100 | Negligible operational impact |
| minor | 100 to < 1000 | Minor disruption, easily absorbed |
| moderate | 1000 to < 10000 | Moderate impact requiring active management |
| major | 10000 to < 100000 | Major operational disruption |
| catastrophic | >= 100000 | Catastrophic loss, existential risk |

### Scenario Requirements

- Minimum 3 scenarios per proposal (INV-ELM-SCENARIOS).
- Each scenario probability must be in [0.0, 1.0].
- Each scenario impact_value must be non-negative.
- Each scenario impact_unit must be one of: `dollars`, `hours`, `severity_units`.
- Each scenario must include a non-empty mitigation string.

### Aggregate Formula Consistency

The `aggregate_expected_loss` field MUST equal the sum of
`probability * impact_value` across all scenarios, within a tolerance
of 1e-6 (INV-ELM-AGGREGATE).

### Confidence Interval Validity

The confidence interval MUST satisfy:
- `lower` <= `aggregate_expected_loss` <= `upper`
- `lower` >= 0
- `upper` >= `lower`
- `confidence_level` in (0.0, 1.0), typically 0.90 or 0.95

### Category Consistency

The `loss_category` MUST match the `aggregate_expected_loss` value
according to the threshold table above (INV-ELM-CATEGORY).

## Enforcement

Validator:
- `scripts/check_expected_loss.py`

Unit tests:
- `tests/test_check_expected_loss.py`

## Event Codes

| Code | Severity | Description |
|------|----------|-------------|
| CONTRACT_ELM_VALIDATED | info | Expected-loss model validated successfully |
| CONTRACT_ELM_MISSING | error | Expected-loss model field absent from proposal |
| CONTRACT_ELM_INVALID | error | Expected-loss model contains invalid data |
| CONTRACT_ELM_THRESHOLD_EXCEEDED | warning | Aggregate expected loss exceeds major/catastrophic threshold |

## Invariants

| ID | Rule |
|----|------|
| INV-ELM-SCENARIOS | Minimum 3 scenarios with valid name, probability, impact_value, impact_unit, and mitigation |
| INV-ELM-AGGREGATE | aggregate_expected_loss equals sum of (probability * impact_value) across all scenarios |
| INV-ELM-CATEGORY | loss_category matches aggregate_expected_loss against threshold boundaries |
| INV-ELM-CONFIDENCE | Confidence interval lower <= aggregate <= upper, bounds non-negative, confidence_level in (0,1) |

## Acceptance Criteria

1. The `change_summary.expected_loss_model` field is required on all subsystem change proposals.
2. At least 3 scenarios are provided, each with name, probability, impact_value, impact_unit, and mitigation.
3. Scenario probabilities are floats in [0.0, 1.0]; impact values are non-negative floats.
4. impact_unit is one of: `dollars`, `hours`, `severity_units`.
5. aggregate_expected_loss equals the sum of (probability * impact_value) for all scenarios.
6. confidence_interval has valid lower, upper, and confidence_level fields with lower <= aggregate <= upper.
7. loss_category is one of: `negligible`, `minor`, `moderate`, `major`, `catastrophic`.
8. loss_category matches the aggregate_expected_loss against defined thresholds (negligible <100, minor 100-1000, moderate 1000-10000, major 10000-100000, catastrophic >=100000).
9. All four event codes (CONTRACT_ELM_VALIDATED, CONTRACT_ELM_MISSING, CONTRACT_ELM_INVALID, CONTRACT_ELM_THRESHOLD_EXCEEDED) are defined.
10. All four invariants (INV-ELM-SCENARIOS, INV-ELM-AGGREGATE, INV-ELM-CATEGORY, INV-ELM-CONFIDENCE) are machine-verifiable.
