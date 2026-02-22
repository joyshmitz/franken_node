# bd-35m7 Contract: Trajectory-Gaming Camouflage Risk Control

## Goal

Prevent malicious actors from evading behavioral trust checks through mimicry by enforcing a maintained adversarial corpus, motif randomization, and hybrid signal fusion.

## Quantified Invariants

- `INV-TGC-MIMICRY-CORPUS`: Mimicry corpus contains `>= 100` patterns and is refreshed at least quarterly.
- `INV-TGC-RECALL`: Detector recall on known mimicry corpus remains `>= 90%`.
- `INV-TGC-HYBRID-FUSION`: Behavioral-channel gaming is insufficient; provenance/code/reputation failures still trigger flags.
- `INV-TGC-RANDOMIZATION`: Consecutive evaluations of the same trajectory use different randomized motif feature subsets.
- `INV-TGC-ADAPTIVE`: Against adaptive adversaries over 10 rounds, detection recall stays `>= 80%`.

## Determinism Requirements

- Re-running verification with identical artifacts yields identical pass/fail verdict.
- Aggregate evaluation is stable under list-order perturbations that preserve metric values.
- Adversarial perturbations (e.g., feature-subset reuse or reduced recall thresholds) deterministically flip the gate result.

## Required Scenarios

1. Scenario A: Known mimicry pattern is flagged with `>= 90%` confidence.
2. Scenario B: Perfect behavioral gaming with suspicious provenance is still flagged by hybrid fusion.
3. Scenario C: Same trajectory evaluated twice uses distinct randomized motif subsets.
4. Scenario D: New mimicry pattern added + retrain preserves recall `>= 90%`.
5. Scenario E: Adaptive adversary over 10 rounds maintains recall `>= 80%`.

## Structured Event Codes

- `TGC-001`: Mimicry corpus integrity and freshness validated.
- `TGC-002`: Known-pattern recall threshold evaluated.
- `TGC-003`: Hybrid signal-fusion safeguard evaluated.
- `TGC-004`: Motif randomization variance evaluated.
- `TGC-005`: Adaptive-adversary resilience evaluation completed.

All events must include stable `trace_id` and model/version context.

## Machine-Readable Artifacts

- `artifacts/12/trajectory_gaming_camouflage_report.json`
- `artifacts/section_12/bd-35m7/verification_evidence.json`
- `artifacts/section_12/bd-35m7/verification_summary.md`

## Acceptance Mapping

- Countermeasure (a): enforced via corpus size/freshness and known-pattern recall thresholds.
- Countermeasure (b): enforced via randomized motif subset divergence across repeated evaluations.
- Countermeasure (c): enforced via fusion checks proving non-behavioral channel failures trigger flags.
- Adaptive-resilience control enforced via 10-round minimum recall floor.
