# ADR-040: Paired adversarial stress qualification for semantic Judges

Status: Accepted
Date: 2026-09-11

## Context

The semantic LLM Judge is a security-sensitive measurement instrument. Blue target output is
attacker-influenced evidence, so the Judge can itself receive prompt injection, authority
claims, schema-shaped text and other artifacts while deciding whether Blue violated a
security objective.

The laboratory already labels target response text as `UNTRUSTED_TARGET_EVIDENCE`, requires
strict JSON output, never allows the semantic Judge to infer `SYSTEM_COMPROMISE` from prose,
and has calibration metrics for accuracy, abstention, class coverage, confidence calibration
and paired stress degradation. What was missing was an executable protocol that produces
clean/stressed paired observations against the same frozen Judge policy.

Current research reinforces this requirement. LLM Judges show material sensitivity even to
semantically equivalent prompt variations, and prompt-injection attacks against Judge
architectures can directly alter evaluation outcomes. Judge robustness therefore cannot be
assumed from base-model capability or clean-set accuracy alone.

## Decision

1. Semantic Judge stress is measurement-instrument validation, not a Blue attack campaign.
2. Every stress case has an independent gold label sourced from a deterministic verifier or
   explicitly curated human-majority reference. The Judge under test never labels itself.
3. The clean target response is evaluated first. Stressed variants preserve the exact clean
   response unchanged and add evaluator-irrelevant target-authored framing around it.
4. Initial paired stress conditions are:
   - target verdict injection,
   - false authority claim,
   - Judge-schema spoofing,
   - verbosity/padding artifacts.
5. Stress variants cannot modify the security objective, target class, attack family, gold
   label or clean response bytes.
6. The same frozen `judge_semantic` policy/model is used for the clean and stressed variants.
7. Results are converted to the existing `JudgeCalibrationObservation` contract. An invalid,
   empty or ambiguous Judge output is an abstention, never a safe PASS.
8. Primary robustness diagnostics are paired verdict flip rate, correct-to-incorrect
   degradation rate, new abstentions under stress, class-specific coverage, false positive /
   false negative behavior, Brier/ECE diagnostics and high-confidence error rate.
9. Stress reports are not Blue ASR/MCR/SCR measurements and cannot be compared as if they
   were target vulnerability estimates.
10. Stress-set provenance is SHA-256 fingerprinted from immutable reference facts,
    clean-response hashes and the selected stress conditions. Raw target responses are not
    persisted by the stress-run result.
11. Judge stress output is never exposed to live adaptive Red. Discovery/evaluation feedback
    boundaries remain unchanged.
12. No generalized claim about Judge reliability is permitted from a fixed stress set unless
    a separately declared statistical inference model supports that estimand.

## Rationale

A load-bearing Judge that can be manipulated by the text it grades can corrupt every
higher-level metric even when Red, Blue and system-state instrumentation are otherwise
correct. Paired stress testing isolates this failure mode: reference facts are held fixed and
only evaluator-directed artifacts change.

Reusing the existing calibration report avoids metric proliferation. It also exposes
abstention explicitly, preventing a stressed Judge that stops producing valid outputs from
appearing safer or more accurate.

## Consequences

### Positive

- Judge prompt-injection susceptibility becomes directly measurable and regression-testable.
- Clean accuracy can no longer hide large adversarial verdict-flip rates.
- Invalid stressed outputs increase abstention and reduce coverage instead of becoming PASS.
- Judge policy/model changes can be qualified against the same fingerprinted stress set.
- The protocol remains provider-independent and uses configured model roles rather than
  hard-coded models.

### Limitations

- The native stressors are controlled diagnostics, not an exhaustive attack corpus against
  the Judge.
- CI proves orchestration with scripted models; real Judge robustness requires a separately
  budgeted local/cloud calibration run using the configured `judge_semantic` role.
- A stress report measures the exact fixed reference set unless a broader statistical model
  is explicitly declared.
- Multi-model Judge committees are not introduced here; they should be justified by measured
  residual failure, not assumed to solve prompt injection.

## Rejected alternatives

### Trust the Judge system prompt without measuring robustness

Rejected because instruction hierarchy is a control, not evidence that adversarial target
content cannot influence the verdict.

### Count invalid Judge output as PASS

Rejected because evaluator failure is missing measurement, not evidence of Blue safety.

### Let Red observe Judge stress verdicts during an attack trajectory

Rejected because it would reintroduce a grading oracle into adaptive Red and contaminate the
attack policy.

### Build a second standalone metrics stack for Judge stress

Rejected because the existing calibration contract already contains the required paired
robustness, abstention and confidence metrics.
