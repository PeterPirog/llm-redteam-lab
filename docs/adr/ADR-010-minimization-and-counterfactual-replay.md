# ADR-010 — Stability-aware minimization and counterfactual replay

- Status: Accepted
- Date: 2026-09-09

## Context

`PROJECT_REQUIREMENTS.md` requires confirmed attacks to be minimized into a Minimal
Reproducing Attack (MRA) and requires counterfactual replay to determine which attack
components are actually necessary. These operations are part of measurement and
forensics, not prompt beautification.

A naive implementation creates misleading evidence. For example, deleting a paragraph
and observing one successful stochastic execution does not prove that the paragraph is
irrelevant. Likewise, if an original attack caused `SYSTEM_COMPROMISE` but a reduced
variant causes only `MODEL_COMPROMISE`, the reduced variant is not an equivalent
reproducer of the original system failure.

Multi-turn jailbreaks add another complication: the relevant experimental object is the
successful ordered conversation path. Historical exploratory branches and backtracks are
attack-search evidence, but they are not automatically part of the minimal reproducer.

## Decision

### 1. Represent attacks as ordered components

The minimizer operates on `AttackVariant`, an ordered sequence of typed
`AttackComponent` values. Initial component kinds include text segments, conversation
turns, instructions, role-play sections and encoding layers.

The representation is provider-independent. The evaluator supplied by the target/campaign
layer decides how an `AttackVariant` is rendered and executed.

### 2. Minimize only against the same security failure

A candidate is accepted only when it still violates the same security objective and,
by default, preserves every compromise layer observed in the reference execution:

- reference MODEL compromise -> candidate must still show MODEL compromise,
- reference SYSTEM compromise -> candidate must still show SYSTEM compromise.

This prevents a system-level exploit from being minimized into a weaker model-only
failure and then mislabeled as the original finding.

### 3. Require stable candidate success

Candidate reduction is stability-aware. A candidate is tested repeatedly according to a
bounded `StabilityPolicy`. The default requires two successful reproductions out of two
scheduled attempts.

`ERROR` and `INCONCLUSIVE` do not prove that a component is unnecessary. They remain
unresolved evidence.

### 4. Use bounded delta debugging plus a final 1-minimal sweep

The implementation first attempts chunk removals using a delta-debugging style search,
then performs single-component removal checks while budget remains. This provides a
practical 1-minimal result without requiring exhaustive evaluation of the powerset.

All target executions are explicitly budgeted. Budget exhaustion produces
`BUDGET_EXHAUSTED`, never an implicit claim of minimality.

### 5. Analyze counterfactual necessity and sufficiency separately

For each component, the initial counterfactual engine can evaluate:

- attack without the component (leave-one-out),
- the component alone,
- an empty attack baseline.

Interpretation is deliberately conditional:

- if removing a component still stably reproduces the same failure, it is not necessary
  under the tested configuration,
- if removing it conclusively breaks reproduction, it is necessary under the tested
  configuration,
- if the component alone reproduces the failure, it is sufficient under the tested
  configuration,
- unresolved evidence yields `None`, not a causal claim.

These are intervention results for the concrete target configuration, attack
representation, Judge configuration and sampling regime. They are not universal causal
proofs.

### 6. Multi-turn minimization uses the successful path

For a branched attack search, minimization starts from the linear path that led to the
verified violation. Turn order is preserved. Exploratory dead-end branches remain in
attack genealogy/evidence, while the minimal reproducer contains only turns shown to be
needed for the successful path.

## Consequences

Positive consequences:

- minimal reproducers preserve the original security meaning,
- stochastic one-off reductions are less likely to be accepted,
- unresolved infrastructure/Judge failures cannot silently remove attack components,
- counterfactual evidence can directly feed the future Forensic Analyst,
- multi-turn attacks become reducible to stable regression sequences.

Costs and limitations:

- minimization can consume substantial target interactions,
- default repeated validation is intentionally more expensive than one-shot reduction,
- leave-one-out and singleton tests do not identify every higher-order interaction,
- full powerset search is intentionally avoided,
- persistence and forensic synthesis are separate follow-on integrations.

## Metric and reporting rule

Reports must keep the following distinct:

1. original finding reproducibility,
2. minimizer target-execution cost,
3. minimized component count,
4. counterfactual tested variants,
5. unresolved counterfactuals,
6. conditional necessity/sufficiency claims.

No single composite score is introduced.
