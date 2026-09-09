# ADR-022: Paired Red Component Ablation

- **Status:** Accepted
- **Date:** 2026-09-09

## Context

The laboratory now contains both a baseline `AdaptiveRedStrategy` and a
`MechanismAwareAdaptiveRedStrategy`. A successful deterministic integration test is
not sufficient evidence that the new strategy improves Red discovery capability.
Multi-turn jailbreak results are highly sensitive to target interactions, turn and
retry budgets, judges, flow control, stochastic sampling, and evaluation-set
composition.

Reporting two independently collected ASRs and subtracting them would therefore
confound strategy effects with experimental conditions. This is especially risky for
small security campaigns, where a few different stochastic outcomes can dominate the
point estimate.

## Decision

Red component comparisons use matched case/replicate pairs under a shared,
hash-bound measurement contract.

Each experiment binds:

- the exact Blue target snapshot,
- the held-out evaluation manifest,
- the Judge fingerprint,
- the campaign budget fingerprint,
- the metric-definition version,
- session semantics,
- the component intentionally changed,
- the baseline Red policy fingerprint,
- the treatment Red policy fingerprint,
- the declared pairing mode.

The two policy fingerprints MUST differ. The held-out manifest, Blue target, Judge,
budget and measurement contract MUST not differ.

## Pairing unit

The statistical unit is:

```text
(case_id, replicate)
```

Both Red arms must contain exactly the same pair keys. Each arm independently passes
the standard held-out evaluation gate, including full case coverage, balanced
replicates and conclusive-only comparative measurement.

Where the target/runtime supports controlled stochastic seeds, the stronger
`CASE_REPLICATE_SEED` mode additionally requires the same non-null seed in both arms.
Where deterministic seeding is unavailable, `CASE_REPLICATE` remains valid but the
weaker stochastic control must be visible in the experiment contract.

## Effectiveness outcomes

The comparison preserves separate security layers:

- objective-violation rate,
- model-compromise rate,
- system-compromise rate.

`MODEL_COMPROMISE` and `SYSTEM_COMPROMISE` MUST NOT be collapsed into a single attack
success label.

For objective violation, matched pairs are classified as:

```text
both succeed
baseline only succeeds
treatment only succeeds
neither succeeds
```

The point delta is:

```text
treatment objective-violation rate - baseline objective-violation rate
```

This delta is descriptive. Statistical evidence for a paired difference is reported
with the two-sided exact McNemar/binomial test over discordant pairs. The framework
also reports a Wilson interval for the treatment win proportion among discordant
pairs. No normal approximation is required for small smoke experiments.

If there are no discordant pairs, the exact McNemar p-value is `1.0`; identical
observed outcomes are not evidence that one policy is superior.

## Cost outcomes

Cost is reported separately from effectiveness. At minimum, paired deltas include:

- target interactions,
- Red planner calls,
- Red mutator calls,
- Red planner + mutator output tokens,
- first-violation ordinal for pairs where both arms succeed.

A negative treatment interaction or first-violation delta means the treatment used
fewer interactions or reached the first violation earlier.

The project MUST NOT combine success and cost into one opaque score by default.

## Budget accounting

`observation_from_run()` derives per-trial Red costs from monotonic
`BudgetSnapshot` before/after values. The recorded turn delta must equal the number
of target interactions in the bounded conversation. A mismatch fails closed because
it indicates that the cost observation is not aligned with the execution being
compared.

## Evaluation versus discovery

Paired component ablation is a controlled evaluation of Red components, not adaptive
cross-trial discovery. When used for a comparative claim:

- the Blue evaluation set is held out,
- Red cross-trial learning is frozen,
- target and Judge identities are pinned,
- budgets are equal,
- the changed component is explicit.

Adaptive within-conversation behavior remains allowed because multi-turn adaptation
is part of the Red policy being evaluated.

## Rationale

This design follows the same measurement principle used elsewhere in the project:
make the experimental unit and denominator explicit, isolate the variable under test,
quantify uncertainty, and fail closed when provenance is incomplete.

It also aligns with current multi-turn jailbreak research emphasizing fixed resource
budgets and evaluator conditions for component attribution, and with NIST TEVV
principles requiring explicit measurement targets and controlled assessment
conditions.

## Consequences

### Positive

- Red improvements can be demonstrated rather than assumed.
- Matched pairs remove case-mixture differences between arms.
- Small-sample uncertainty remains visible.
- Model and system compromise remain independently measurable.
- Cost improvements can be distinguished from effectiveness improvements.
- The framework can later compare prompt generators, refiners, mechanism policies,
  flow controllers, or other Red modules under the same contract.

### Negative

- A credible ablation requires both arms to run every held-out replicate.
- Paired tests consume more target interactions than a one-arm smoke test.
- Seed pairing is only available when the underlying target/runtime exposes a usable
  stochastic seed.

These costs are accepted because an uncontrolled comparison would provide a stronger
number with weaker evidentiary value.
