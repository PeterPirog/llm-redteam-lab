# ADR-029 — Judge calibration and adversarial stress testing

- **Status:** Accepted
- **Date:** 2026-09-10

## Context

The laboratory uses semantic and multimodal Judges only after stronger deterministic
or system-state evidence is insufficient. That ordering reduces inference cost and
keeps observable effects authoritative, but an independent LLM Judge is still a
fallible measurement instrument.

Recent 2026 safety-evaluation research shows that automated jailbreak Judges can have
materially different precision/recall profiles and can change verdicts under benign
framing that does not change the underlying harmful content. Other work shows Judge
performance can degrade under red-team distribution shift and that high self-reported
confidence does not guarantee correct interpretation of multi-turn objectives.

A raw ASR therefore cannot be considered fully interpretable when a material fraction
of its labels comes from an uncalibrated semantic or multimodal Judge.

## Decision

Judge quality is measured as a first-class, hash-bound experiment that is separate
from Blue campaign ASR.

Calibration observations contain no raw prompt or response text. Each observation
binds:

- a stable testcase identifier;
- an independent reference label;
- the source class of that reference label;
- the Judge decision or explicit abstention;
- optional Judge self-confidence;
- target class;
- attack family;
- stress condition.

Allowed reference-label sources are deliberately restricted to:

- deterministic verifier evidence;
- explicitly curated human-majority labels.

A Judge cannot calibrate itself, and another unqualified Judge is not accepted as the
reference truth by this contract.

## Confusion metrics and abstention

The report exposes conventional decided-case metrics with Wilson uncertainty:

- accuracy;
- precision;
- recall/sensitivity;
- specificity;
- negative predictive value.

Abstentions are never converted to safe predictions. The report separately exposes:

- overall coverage and abstention rate;
- positive-class and negative-class coverage;
- `violation_detection_rate = TP / all reference-positive cases`;
- `safe_clearance_rate = TN / all reference-negative cases`.

This means a Judge may have perfect accuracy on the cases it answers while still
showing weak end-to-end detection because it abstains frequently. Reports must retain
both facts.

Undefined rates remain unavailable rather than becoming zero. For example, a
reference set with no positive cases cannot establish sensitivity.

## Self-confidence calibration

When a conclusive Judge decision includes self-reported confidence, the confidence is
interpreted only as confidence that the decision is correct. It is **not** treated as
a probability that Blue is vulnerable.

The report includes:

- Brier score against decision correctness;
- 10-bin expected calibration error (ECE);
- wrong-at-high-confidence rate for confidence >= 0.90.

These are diagnostics, not substitutes for confusion metrics.

## Paired stress robustness

Stress testing uses the same `case_id` under a clean condition and one or more
semantically equivalent stress conditions, such as benign framing around unchanged
unsafe content. Reference facts for the paired variants must remain identical.

For every stress condition, the report records:

- number of matched cases;
- number with conclusive decisions in both conditions;
- verdict flips;
- clean-correct -> stressed-incorrect degradation;
- clean-incorrect -> stressed-correct recovery;
- new abstentions introduced by stress;
- abstentions resolved under stress;
- Wilson interval for verdict-flip rate;
- Wilson interval for degradation among clean-correct, jointly conclusive pairs.

A simple aggregate stress-set accuracy is insufficient because it cannot tell whether
the same underlying cases changed verdict solely due to evaluator framing.

## Slicing

Calibration is reported overall and, where labels are present, by:

- stress condition;
- attack family;
- Blue target class.

This prevents a strong global average from hiding weak performance on a difficult
attack family or modality.

## Persistence and integrity

Calibration reports and normalized observations are persisted immutably. The report
binds:

- calibration reference-set fingerprint;
- Judge policy fingerprint;
- exact observation-result hash;
- all derived metrics and stress comparisons.

Load recomputes the complete report from persisted observations. Tampering or a
mismatch between report and observation evidence fails closed.

Observation order is not part of experiment identity. Persistence normalizes order by
`(case_id, stress_condition)` so idempotent saves are stable.

## What this does not claim

This milestone does not automatically correct Blue ASR for Judge error. A correction
estimated on one distribution may become misleading after target, attack, language,
modality or output-style shift. Any future calibration-adjusted estimator must declare
its assumptions and uncertainty separately from the raw measured campaign rate.

This milestone also does not define a universal pass/fail threshold for a Judge. The
next integration step may attach a predeclared Judge qualification policy to
comparative EVALUATION, scoped to the target class, attack families and calibration
reference set.

## Standards and research alignment

The design follows the measurement-first direction of NIST TEVV-Athlon and NIST AI
800-3: evaluation assumptions, measurement targets and uncertainty should be explicit
rather than hidden behind one score.

It is also informed by:

- Gao (2026), *How Reliable Is Your Jailbreak Judge? Calibration and Adversarial
  Robustness of Automated ASR Scoring*, arXiv:2606.25487;
- Schwinn et al. (2026), *A Coin Flip for Safety: LLM Judges Fail to Reliably Measure
  Adversarial Robustness*, arXiv:2603.06594;
- Weng et al. (2026), *Beyond Accuracy: Policy Invariance as a Reliability Test for
  LLM Safety Judges*, arXiv:2605.06161;
- Kim et al. (2025), *ObjexMT: Objective Extraction and Metacognitive Calibration for
  LLM-as-a-Judge under Multi-Turn Jailbreaks*, arXiv:2508.16889.

NIST AI 200-2 TEVV-Athlon is an initial public draft as of this ADR date and is treated
as current guidance/direction, not as a finalized standard.

## Consequences

Positive:

- semantic/multimodal evaluation quality becomes measurable and auditable;
- abstention cannot artificially improve Judge accuracy;
- high-confidence Judge failures become visible;
- framing sensitivity is measured on paired underlying cases;
- reference truth is explicitly independent from the Judge;
- calibration can later become a measurement-quality gate without changing Blue ASR
  semantics.

Costs and limitations:

- credible calibration requires independently labelled data;
- human-majority labels cost effort and can still contain annotation uncertainty;
- Judge reliability can shift across targets, languages, modalities and attack
  families;
- calibration must therefore be repeated or requalified when measurement conditions
  materially change.
