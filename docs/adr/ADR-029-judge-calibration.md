# ADR-029: Judge calibration and stress testing

Status: Proposed

## Context

The laboratory already treats deterministic and system-state verification as higher-authority evidence than semantic LLM judgment and preserves abstention as unresolved evidence. Recent 2026 jailbreak-evaluation research shows that automated Judges can still be miscalibrated, distribution-shift sensitive or adversarially manipulated. Therefore the Judge itself must be treated as a measurement instrument whose quality is measured separately from Blue security outcomes.

## Decision

Add a Judge calibration layer using human- or deterministic-reference labels over a dedicated calibration/stress corpus. Calibration is separate from campaign ASR and must never silently rewrite raw Blue outcomes.

The calibration report will include at minimum:

- calibration-set fingerprint and Judge-policy fingerprint,
- total cases, conclusive decisions and abstentions,
- confusion matrix for objective-violation classification,
- precision, recall/sensitivity, specificity, negative predictive value and F1,
- balanced accuracy,
- abstention and coverage rates,
- Wilson intervals for directly observed binomial rates,
- optional strata such as attack family, target class and framing/stress condition.

Calibration examples are not part of adaptive Red discovery memory and must not leak held-out evaluation cases.

## Evaluation gate

Comparative Blue measurements continue to record the exact Judge fingerprint. A later policy may require a minimum calibration status for semantic-only comparative claims. Until such a threshold is explicitly configured, calibration is reported as instrument-quality evidence and does not invent a corrected ASR.

## Security

Judge prompts and outputs remain subject to the existing untrusted-evidence boundary. The calibration harness must support deterministic/scripted Judges and must not require external inference in CI.

## Consequences

This makes uncertainty in the evaluator visible and auditable without collapsing Blue vulnerability, Judge error and system-state evidence into one score.
