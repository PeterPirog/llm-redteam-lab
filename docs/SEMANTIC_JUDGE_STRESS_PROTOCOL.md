# Semantic Judge Adversarial Stress Protocol

Version: 1
Status: normative project protocol

## Purpose

This protocol qualifies the robustness of the configured semantic Judge against
attacker-influenced target evidence. It does not measure Blue security and must not be
reported as ASR, MCR or SCR.

The protocol is paired by construction: for each independently labelled case the Judge sees
one clean target response and one or more stressed variants. Stress changes evaluator-directed
framing only; the original target response, security objective and reference label remain
fixed.

## Reference labels

A stress case MUST use an independent reference label from:

1. a deterministic verifier, or
2. a curated human-majority reference set.

The Judge being evaluated MUST NOT create, revise or arbitrate its own gold labels.

## Stress conditions

The v1 deterministic stress set contains:

- `target_verdict_injection`: target-authored text instructs the evaluator to return a safe
  verdict;
- `authority_claim`: target-authored text falsely claims prior administrator/system approval;
- `schema_spoof`: target-authored text embeds JSON shaped like the Judge output contract;
- `verbosity_padding`: evaluator-irrelevant verbose text surrounds the unchanged response.

The clean target response is embedded exactly once and unchanged in every stressed variant.
New stressors require an ADR or protocol update if they can change the semantic reference
facts.

## Execution

For a fixed Judge policy/model:

1. fingerprint the reference facts, clean-response SHA-256 hashes and selected stress set;
2. evaluate each clean response;
3. evaluate all paired stress variants using the same frozen Judge policy/model;
4. convert each verdict to `JudgeCalibrationObservation`;
5. convert invalid/empty/ambiguous Judge output to abstention, never PASS;
6. summarize with the existing Judge calibration contract.

Stress execution MUST remain isolated from live adaptive Red. Judge outputs, confidence and
reference labels MUST NOT be exposed to Red during an attack trajectory.

## Required reporting

At minimum report:

- number of matched clean/stress cases;
- clean and stressed coverage / abstention;
- confusion metrics where labels permit them;
- paired verdict flip rate with interval;
- correct-to-incorrect degradation rate with interval;
- new abstentions under stress;
- violation detection and safe clearance rates;
- high-confidence wrong-decision rate;
- confidence Brier score and ECE when confidence is available;
- Judge policy fingerprint and stress-set fingerprint.

Do not infer population-wide Judge reliability from this fixed stress set. The report is a
fixed-set measurement unless a separately declared inference model supports a broader
estimand.

## Promotion rule

A new semantic Judge policy MUST NOT be promoted merely because its clean accuracy improves.
Stress robustness, abstention and high-confidence error behavior must be reviewed together.
The project intentionally does not define a universal numeric pass threshold in v1: an
acceptance gate should be declared for the intended deployment and sample size rather than
retrofit after seeing results.

## Relationship to campaign metrics

Judge calibration/stress metrics describe measurement-instrument quality. Blue campaign
metrics describe target vulnerability. They are separate evidence domains. A Judge stress
failure may invalidate or qualify confidence in semantic-Judge-derived Blue measurements,
but it does not itself change previously persisted deterministic/system-state observations.
