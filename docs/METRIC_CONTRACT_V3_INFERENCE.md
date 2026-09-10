# Metric Contract v3 — Inference Scope and Benchmark Interpretation

Status: implemented
Last verified: 2026-09-10

This document refines metric interpretation without replacing
`PROJECT_REQUIREMENTS.md`. The architectural source of truth remains authoritative.

## Purpose

Security evaluation must distinguish two different questions:

1. **What happened on this exact held-out evaluation set under these recorded
   conditions?**
2. **What should we expect over a broader population of similar attacks?**

Those questions require different inferential assumptions. Reporting one Wilson
interval does not make them equivalent.

NIST AI 800-3 explicitly distinguishes performance conditioned on a fixed benchmark
from generalized performance over potential similar test items. `llm-redteam-lab`
therefore makes inferential scope an explicit part of the evaluation result.

Primary reference:

- NIST AI 800-3, *Expanding the AI Evaluation Toolbox with Statistical Models*:
  https://www.nist.gov/publications/expanding-ai-evaluation-toolbox-statistical-models

## Supported scope: `FIXED_CORPUS`

The standard `summarize_evaluation()` path implements only `FIXED_CORPUS` inference.
The estimate is conditioned on:

- the exact held-out/sequestered evaluation manifest,
- the pinned Blue target snapshot,
- the frozen Red policy,
- the Judge policy,
- the campaign/flow budgets,
- the recorded session semantics,
- the metric definition version.

The result may be compared with another target or Red configuration only when the
normal comparability gates are satisfied.

This is intentionally conservative. The framework should produce a narrower claim
that is defensible rather than a broad claim unsupported by the experiment design.

## Statistical and aggregation units

For ordinary single-turn evaluation, one case/replicate execution is the stochastic
observation.

For multi-turn evaluation, one complete bounded conversation remains one Blue
security trial. Individual turns, retries, branches and backtracks are resource and
search-process observations, not additional ASR trials.

Metric Contract v3 records:

```text
statistical_unit = case_replicate
aggregation_unit = evaluation_case
```

Balanced replicates are required by the comparative EVALUATION gate. This prevents
cases with more retries from receiving greater implicit weight.

## Primary estimands

The inference contract exposes three primary security estimands independently:

- objective violation rate (ASR semantics),
- model compromise rate (MCR),
- system compromise rate (SCR).

The `MODEL_COMPROMISE` / `SYSTEM_COMPROMISE` distinction remains architectural and is
not collapsed for statistical convenience.

## Case-level heterogeneity

A global rate can hide important structure. For each estimand, the fixed-corpus
contract therefore reports per-case repeated-trial estimates and descriptive
heterogeneity across the exact manifest:

- unweighted macro mean of per-case observed rates,
- minimum case rate,
- maximum case rate,
- observed between-case variance,
- per-case successes/trials and Wilson interval.

These diagnostics answer whether observed vulnerability is broad or concentrated in a
small subset of attack cases.

They are descriptive properties of the fixed evaluation set. The between-case
variance is **not** a population variance estimate and must not be presented as one.

## Wilson interval interpretation

Wilson intervals remain useful for transparent small-sample Bernoulli summaries.
They describe uncertainty under the repeated-trial/binomial interpretation used by
the current metric layer.

They do **not** by themselves justify a claim such as:

> this target has X% vulnerability across all possible jailbreaks

A fixed-corpus interval must stay labelled as fixed-corpus evidence.

## `GENERALIZED_POPULATION` is fail-closed

The enum value exists so the requested inferential scope is explicit. The standard
evaluation summarizer currently rejects `GENERALIZED_POPULATION`.

This is deliberate. Generalized inference must not be enabled by changing a report
label.

A future generalized backend must require, at minimum:

- an explicitly defined target population of attacks/test items,
- a documented item-selection or probability-sampling mechanism, or a predeclared
  superpopulation statistical model,
- versioned analysis assumptions,
- an analysis-model fingerprint,
- treatment of repeated observations within the same testcase,
- attack-family and testcase heterogeneity rather than implicit IID assumptions,
- uncertainty appropriate to the declared estimand,
- diagnostics for model fit and sensitivity where model-based inference is used.

A generalized linear mixed model may be one candidate when the experimental design
and sample size justify it, consistent with NIST AI 800-3. It is not introduced merely
because it is statistically sophisticated.

## Discovery remains separate

Adaptive DISCOVERY is optimized from previous outcomes. Its observed yield measures
Red search effectiveness and may guide future attack hypotheses. It is not silently
upgraded to a Blue vulnerability population estimate.

Held-out EVALUATION freezes cross-trial Red learning. Adaptation inside one bounded
multi-turn conversation may remain part of the frozen attack policy.

## Multi-turn sequence claims

Metric Contract v3 is used together with
`docs/MULTITURN_EVALUATION_PROTOCOL_2026.md`.

A high multi-turn ASR does not prove that conversational memory caused the uplift.
When that mechanism matters, use the matched retained-context versus reset-each-turn
control and paired statistics under comparable budgets.

Current multi-turn research reinforces this requirement:

- MT-JailBench (2026) shows that budgets, evaluators, retry rules and flow-control
  choices can materially change attack rankings:
  https://arxiv.org/abs/2605.11002
- MultiBreak (2026) shows that diverse multi-turn trajectories expose vulnerabilities
  missed by simpler evaluation:
  https://arxiv.org/abs/2605.01687
- *Multi-Turn Jailbreaks Are Simpler Than They Seem* shows that some apparent
  multi-turn advantage can approach repeated single-turn resampling once attacker
  feedback opportunity is controlled:
  https://arxiv.org/abs/2508.07646

The project therefore measures both sequence effectiveness and sequence dependence.

## Judge quality remains a separate measurement layer

Judge calibration/stress-test metrics are not folded into ASR. The Judge is itself a
measurement instrument whose precision, recall, abstention, confidence calibration
and stress robustness must remain visible.

A weak Judge does not make a target safer; it makes the measurement less trustworthy.

## Standards alignment

This metric contract complements, rather than replaces:

- NIST AI 800-3 statistical evaluation guidance,
- NIST AI 200-2 TEVV-Athlon initial public draft,
- OWASP GenAI LLM Top 10 2026,
- OWASP Agent Control Standard,
- MITRE ATLAS,
- OpenTelemetry semantic conventions.

The external frameworks are classification, governance and measurement references.
They do not override the project's evidence hierarchy or compromise semantics.

## Reporting rule

A report produced through the standard EVALUATION path should be interpretable as:

> Under the exact recorded target, Red policy, Judge, budget and held-out manifest,
> the following objective/model/system compromise outcomes were observed.

It should **not** be silently shortened to:

> the model is X% vulnerable.

That difference is part of the security result, not editorial wording.
