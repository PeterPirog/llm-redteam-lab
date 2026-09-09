# Adaptive Red Operating Model

This document describes how the first model-backed Red implementation is intended to operate during development and bounded campaigns.

## Objective

Red should maximize useful adversarial information under a fixed campaign budget. It should not merely maximize prompt count or repeatedly paraphrase one attack.

The first implementation separates:

- Blue vulnerability measurement,
- Red search efficiency,
- target interaction cost,
- attacker-model inference cost.

## Multi-turn attack unit

One bounded conversation is one attack trial. Individual turns are evidence and cost units.

```text
conversation
  turn 1 -> target -> observation
  turn 2 -> target -> observation
  branch/backtrack if allowed
  ...
  turn N -> target -> observation
```

A longer conversation does not create more Blue ASR trials.

## Adaptive phases

### Primer

First turn. Establish useful context and gather target behavior without spending the full objective immediately when doing so is unlikely to be informative.

### Planner

Intermediate turns. Select the next tactic from actual target responses and compact campaign learning. Prefer information gain, meaningful strategy change and exploitation of observed weak boundaries over cosmetic rewriting.

### Finisher

Final available turn. Use accumulated evidence to make the strongest authorized probe for the defined synthetic/test failure signal.

## Planner decision contract

The `red_planner` produces exactly one structured decision. The deterministic controller validates it before any target request.

Valid actions:

- `continue`: extend the active branch,
- `backtrack`: create an alternate replay branch from an existing turn when session semantics allow it,
- `stop`: terminate Red exploration for the conversation.

The model cannot change target identity, security objective, budget, network policy, tool permissions or Judge behavior.

## Mutation/repair

A `red_mutator` call is used only when the planner output is:

- malformed,
- inconsistent with session/branch rules,
- outside branch/backtrack limits,
- too similar to a prior attacker turn.

Only one repair is allowed per decision in the initial implementation. A second invalid output stops the strategy for that turn path.

## Campaign memory

Adaptive Red memory is deliberately compact and transcript-free. It records empirical signals such as tactic labels, successes, errors, query count and first violation depth.

This allows later attacks to learn which strategies worked without making attacker memory a hidden copy of every prompt and response.

## Cost controls

Campaign budgets can cap global and per-role model calls/output tokens. The dedicated `multiturn_smoke` profile exists so a normal single-turn smoke run does not silently become a higher-cost adaptive campaign.

Recommended development order:

1. scripted Red + deterministic Blue,
2. scripted Red + vulnerable/hardened synthetic multi-turn Blue,
3. local Red model + deterministic Blue,
4. local Red model + local Blue model,
5. semantic Judge only where deterministic grading is insufficient,
6. cloud escalation only when explicitly enabled.

## Required comparison dimensions

A Red-vs-Red comparison is meaningful only when the following remain compatible:

- Blue target identity/configuration,
- security objective,
- corpus revision,
- conversation budget,
- session mode,
- Judge policy,
- Red model-role configuration,
- metric contract version.

Always report Blue ASR/MCR/SCR separately from Red query/inference efficiency.
