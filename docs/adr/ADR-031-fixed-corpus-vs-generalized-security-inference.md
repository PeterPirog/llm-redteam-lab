# ADR-031 — Fixed-Corpus vs Generalized Security Inference

Status: Accepted
Date: 2026-09-10

## Context

`llm-redteam-lab` already separates adaptive DISCOVERY from held-out EVALUATION and
binds comparative measurements to a target snapshot, frozen Red policy, Judge,
budgets and evaluation manifest. However, a conventional campaign rate plus a
confidence interval can still be over-interpreted as a property of an undefined
population of all possible attacks.

NIST AI 800-3 distinguishes fixed-benchmark performance from generalized performance
and shows that uncertainty depends on the statistical model and evaluation estimand.
Security benchmarks have the same problem, amplified by heterogeneous attack families,
repeated stochastic trials and multi-turn flow-control differences.

## Decision

The standard EVALUATION summarizer SHALL explicitly label its inferential scope as
`FIXED_CORPUS`.

It SHALL expose:

- metric-contract version,
- statistical unit,
- aggregation unit,
- ASR/MCR/SCR estimands,
- per-case repeated-trial estimates,
- descriptive between-case heterogeneity,
- an explicit statement that generalized claims are unsupported.

The standard summarizer SHALL reject a requested `GENERALIZED_POPULATION` scope until
a dedicated generalized-inference backend exists.

A Wilson interval SHALL NOT be treated as sufficient evidence for population
generalization.

For multi-turn attacks, one bounded conversation remains one Blue security trial.
Turns/backtracks/branches remain resource/search observations. Sequence-memory claims
require the separate matched retained-context versus reset-each-turn intervention.

## Rationale

Failing closed on inference is preferable to producing a numerically precise but
semantically unsupported security claim. This decision improves interpretability
without adding an unnecessary heavy statistical dependency or pretending that current
corpora are probability samples from a well-defined attack population.

Case-level diagnostics also expose vulnerability concentration that a global ASR can
hide while remaining simple enough for deterministic tests and smoke campaigns.

## Consequences

Positive:

- reports become harder to overstate,
- target/version comparisons retain clear experimental scope,
- heterogeneous testcase behavior is visible,
- multi-turn metrics remain compatible with the sequence-level trial definition,
- a future GLMM/Bayesian/probability-sampling backend has an explicit integration
  boundary rather than silently changing existing metric semantics.

Negative:

- the framework will refuse generalized claims even when an operator informally
  believes a benchmark is representative,
- additional design work is required before population-level vulnerability estimates
  can be reported.

## Future generalized backend gate

Before `GENERALIZED_POPULATION` can be enabled, an implementation must define and
version at least:

1. the target population / superpopulation,
2. case-selection or probability-sampling design, or a predeclared statistical model,
3. dependence structure for repeated trials and multi-turn observations,
4. attack-family/testcase heterogeneity treatment,
5. analysis-model fingerprint and assumptions,
6. fit/sensitivity diagnostics,
7. uncertainty appropriate to the estimand.

No generalized backend should be added until campaign data and experimental design
justify the additional complexity.

## Architectural alignment

This decision strengthens evidence, reproducibility and explainability without
changing the authoritative `MODEL_COMPROMISE` / `SYSTEM_COMPROMISE` distinction or
provider-independent Red/Blue/Judge architecture.
