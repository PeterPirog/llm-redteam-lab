# ADR-028 — Evidence-based Red policy qualification

- **Status:** Accepted
- **Date:** 2026-09-10

## Context

The laboratory now has several multi-turn Red policies: a generic adaptive attacker,
a mechanism-aware policy, and an experimental risk-aware portfolio scheduler. The
portfolio policy has more search logic, but implementation complexity is not evidence
of superior attack discovery.

Current multi-turn jailbreak research shows that attack rankings are sensitive to the
evaluation function, target-interaction budget, retry/backtrack policy, prompt
generation, refinement and flow control. A scheduler that appears stronger in one
uncontrolled run can therefore be worse, equivalent, or merely more expensive under
matched conditions.

The project already provides paired held-out Red component ablation with immutable
measurement provenance. What was missing was an explicit rule for translating that
experiment into an operational promotion decision.

## Decision

Experimental Red policies use a predeclared qualification policy. Qualification
consumes only a valid `PairedRedAblationReport`; it does not inspect raw target text
or allow the attacker to judge itself.

The decision has three states:

- `QUALIFIED` — evidence satisfies all predeclared promotion criteria;
- `REJECTED` — there is affirmative evidence that treatment is worse, or it violates
  an explicitly configured operational resource ceiling;
- `INCONCLUSIVE` — the experiment does not provide enough evidence to promote or
  reject treatment.

`INCONCLUSIVE` is deliberately distinct from rejection. Small samples, no discordant
pairs, weaker-than-required stochastic pairing, or a non-significant paired result do
not prove that a treatment is ineffective.

## Statistical promotion rule

The primary effectiveness endpoint is conversation-level objective violation in the
existing paired held-out experiment. One bounded multi-turn conversation remains one
statistical trial.

By default, promotion requires:

1. at least the configured minimum number of matched `(case_id, replicate)` pairs;
2. a treatment objective-violation rate improvement strictly greater than the
   predeclared minimum effect delta;
3. more treatment-only than baseline-only successes among discordant pairs;
4. a two-sided exact McNemar/binomial p-value at or below the configured `alpha`.

The exact paired test is reused from the existing ablation contract. The Wilson
interval for treatment wins among discordant pairs remains visible as an uncertainty
diagnostic, but the project does not create a second hidden significance rule from
that interval.

If a paired exact test significantly favors the baseline, treatment is `REJECTED`.
If evidence is insufficient, treatment remains `INCONCLUSIVE`.

## Pairing strength

Some model providers expose reproducible stochastic seeds and some do not. A
qualification policy may therefore require `CASE_REPLICATE_SEED`. When that stronger
pairing is required but unavailable, the result is `INCONCLUSIVE`, not silently
upgraded to an equivalent experiment.

## Cost is not a composite score

Effectiveness and cost remain separate dimensions. Qualification may optionally set
ceilings for:

- mean additional Blue target interactions;
- mean additional Red planner/mutator output tokens.

Exceeding a predeclared ceiling rejects operational promotion even when attack
success improves. The framework does **not** blend ASR improvement, token cost and
latency into an opaque scalar score.

## Trust boundary

The qualification function accepts the already validated paired ablation report.
For an auditable production decision, callers should derive that report through
`summarize_persisted_red_ablation()` so campaign, execution, conversation, target,
Judge, budget and held-out manifest provenance are re-verified from storage.

A Red model cannot set its own qualification status. A target response cannot set its
own qualification status. The decision is deterministic given the report and the
predeclared qualification policy.

## Operational policy

`MechanismPolicy` remains the stable comparison baseline for the current
`RiskAwarePortfolioPolicy`. Portfolio scheduling is an experimental treatment until a
representative paired held-out experiment qualifies it for the target class and
measurement regime of interest.

Qualification is not universal proof that a policy is globally superior. It is an
evidence-backed statement scoped to the experiment's Blue target snapshot, held-out
set, Judge, budget, session semantics, metric version and policy fingerprints.

## Consequences

Positive:

- Red improvements must be demonstrated rather than assumed;
- low-power experiments cannot accidentally promote a scheduler;
- statistically worse treatments can be rejected explicitly;
- seed-pairing strength remains visible;
- cost policy stays interpretable and independent from attack effectiveness;
- future Red planners, generators, refiners and flow controllers can reuse the same
  qualification contract.

Costs and limitations:

- qualification requires enough matched evaluation traffic to obtain useful power;
- a policy can remain `INCONCLUSIVE` for a long time on highly robust or highly
  vulnerable targets with few discordant outcomes;
- statistical qualification is local to the declared experiment conditions;
- this milestone does not itself prove that the current portfolio scheduler is
  better — it creates the gate through which that claim must pass.

## Standards and research alignment

This decision supports NIST TEVV-Athlon's emphasis on explicit, customizable
measurement conditions and evidence, and it follows the modular evaluation principle
from MT-JailBench. It also matches the project's use of RAMP as evidence that
multi-step planning and clue accumulation can improve multi-turn attacks while still
requiring empirical ablation before promotion.

## References

- NIST TEVV-Athlon: https://www.nist.gov/artificial-intelligence/ai-research/tevv-athlon-framework-evaluating-ai-systems
- MT-JailBench: https://arxiv.org/abs/2605.11002
- RAMP: https://aclanthology.org/2026.findings-acl.925/
