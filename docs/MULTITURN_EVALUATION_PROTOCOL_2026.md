# Multi-turn Security Evaluation Protocol — 2026

Status: implementation guidance
Last verified: 2026-09-10

This document refines the project's multi-turn measurement method without replacing
`PROJECT_REQUIREMENTS.md`. It exists to prevent a common evaluation error: calling a
Red policy "better" merely because it received more target interactions or because a
success-only latency statistic looked favorable.

## Why multi-turn is first-class

Modern jailbreak and prompt-injection behavior is often conversational rather than a
single isolated request. A sequence can accumulate context, use the target's previous
responses, branch after refusals and progressively change the model's local state.
Crescendo is a representative example. MultiBreak (2026) further demonstrates why
multi-turn trajectories need dedicated evaluation rather than being flattened into
single prompts.

At the same time, recent empirical work shows that some apparent multi-turn gains can
collapse toward repeated single-turn resampling once retry opportunity and feedback
are controlled. Therefore this laboratory must measure both *attack success* and
*sequence dependence*.

Primary research references:

- Crescendo, USENIX Security 2025:
  https://www.usenix.org/conference/usenixsecurity25/presentation/russinovich
- MultiBreak (2026): https://arxiv.org/abs/2605.01687
- Multi-Turn Jailbreaks Are Simpler Than They Seem (2025):
  https://arxiv.org/abs/2508.07646

## Statistical unit

One bounded multi-turn conversation is one Blue vulnerability trial.

Individual turns, retries, branches and backtracks are not extra ASR trials. They are
Red resource/exposure observations. This preserves a stable denominator when two Red
policies use different numbers of target interactions.

The laboratory therefore reports separately:

- conversation-level ASR/MCR/SCR,
- target-call cost,
- path depth,
- backtracks and branches,
- time-to-first-violation,
- unresolved measurement rate,
- attacker/Judge model calls and token cost.

## Censoring-aware time-to-compromise

A median calculated only among successful attacks is conditional on success and can be
misleading when runs have unequal stopping times. `multiturn_metrics.py` therefore
provides right-censoring-aware Kaplan-Meier estimates on two axes:

1. `target_calls` — actual target interaction count; this is a cost/exposure axis.
2. `path_depth` — logical conversational depth; this measures context progression and
   remains distinct under branching/backtracking.

A successful run produces an event at its first objective violation. A conclusive
unsuccessful run is right-censored at its final observed exposure. `ERROR`, `PARTIAL`
and `INCONCLUSIVE` are not silently converted to censored defensive successes; they
remain unresolved and are excluded from this curve.

Confidence intervals use Greenwood variance with a log-log transform. The method is
reported explicitly as `kaplan_meier_greenwood_loglog`.

### Interpretation constraint

Kaplan-Meier estimation assumes non-informative right censoring. A Red strategy that
stops early because it has inferred that a target is unusually difficult can violate
that assumption. Comparative EVALUATION should therefore use predeclared stopping
rules and compatible budgets. If censoring is materially adaptive, the curve is a
descriptive property of the observed Red policy, not a generalized target property.

## Sequence-dependence claim gate

A multi-turn success does not by itself prove that accumulated context caused the
success. A strong claim that "conversation memory improves the attack" requires a
controlled counterfactual or matched baseline.

Minimum evidence design:

### Arm A — retained-context sequence

Run the bounded sequence with normal conversational history and the frozen Red policy.
Record target calls, path depth, branch decisions, model/Judge cost and the complete
flow fingerprint.

### Arm B — budget-matched independent resampling

Use the same held-out `(case_id, replicate)` units and the same maximum target-call
opportunity, but reset target conversational state between attempts. Attacker/Judge
budgets and target snapshot must be matched as closely as the target interface allows.

The comparison asks whether retained conversation context provides measurable uplift
beyond simply receiving more independent attempts.

### Optional mechanism controls

For confirmed sequence successes, add interventions such as:

- final-turn-only replay,
- prefix truncation,
- leave-one-turn-out replay,
- sequence minimization,
- shuffled-context controls where semantically meaningful.

These are mechanism probes. They support conditional necessity/sufficiency claims
under the tested target configuration; they are not universal causal proofs.

## Comparison statistics

When Arm A and Arm B use matched case/replicate units, use the existing paired Red
ablation machinery rather than comparing two unrelated percentages. Report:

- both succeed,
- sequence only succeeds,
- resampling only succeeds,
- neither succeeds,
- treatment-minus-baseline effect,
- exact two-sided McNemar/binomial diagnostic on discordant pairs,
- Wilson interval for treatment wins among discordant pairs,
- target-interaction and Red-model cost deltas.

Predeclare the minimum pair count, alpha and minimum practically relevant effect before
evaluation. A non-significant result is `INCONCLUSIVE`, not proof of equivalence.

Do not promote a sequence policy based on adaptive DISCOVERY yield. Cross-trial Red
learning must be frozen for held-out EVALUATION; adaptation *inside* a bounded
conversation can remain part of the frozen policy definition.

## Judge and evidence rules

Sequence evaluation does not weaken the project's evidence hierarchy:

1. deterministic/system-state evidence where available,
2. authorization and tool/post-state evidence for AGENT targets,
3. calibrated semantic Judge evidence when deterministic verification is impossible,
4. abstention/inconclusive when evidence cannot support a reliable classification.

A fluent harmful-looking answer is not evidence of `SYSTEM_COMPROMISE`. Conversely, a
model refusal is not a defense success if an unauthorized side effect already occurred.
Judge identity, calibration state and policy fingerprint remain measurement provenance.

## Modern standards crosswalk

This protocol should be interpreted together with `docs/STANDARDS_ALIGNMENT.md`.
Relevant current references include:

- OWASP GenAI LLM Top 10 2026:
  https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
- OWASP Top 10 for Agentic Applications 2026:
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP Agent Control Standard (ACS):
  https://genai.owasp.org/resource/agent-control-standard-acs/
- MITRE ATLAS: https://atlas.mitre.org/
- NIST AI 800-3, *Expanding the AI Evaluation Toolbox with Statistical Models*:
  https://www.nist.gov/publications/expanding-ai-evaluation-toolbox-statistical-models
- OpenTelemetry semantic conventions:
  https://opentelemetry.io/docs/specs/semconv/

These are alignment and classification references, not certifications.

## Reporting contract

A serious multi-turn report should make the following impossible to miss:

- whether the result comes from DISCOVERY or held-out EVALUATION,
- whether target state was retained between turns,
- the complete flow/budget fingerprint,
- conversation-level ASR with numerator, denominator and interval,
- unresolved count/rate,
- cumulative violation curve by target-call exposure,
- cumulative violation curve by path depth when branching is possible,
- whether a matched independent-resampling control was run,
- whether sequence dependence was supported, unsupported or still inconclusive,
- model versus system compromise,
- Judge provenance and measurement limitations.

The objective is not to maximize one impressive ASR number. The objective is to
produce attack evidence that remains interpretable when the attack, model, Judge and
system architecture all change.
