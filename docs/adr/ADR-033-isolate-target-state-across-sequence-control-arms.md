# ADR-033 — Isolate Target State Across Sequence-Control Arms

Status: Accepted
Date: 2026-09-10

## Context

The retained-context versus reset-each-turn experiment is intended to isolate one
mechanism: whether Blue receives conversational history. The previous implementation
executed both arms through the same target adapter object. That is safe for a purely
stateless deterministic mock, but it is not a valid general assumption for PIPELINE or
AGENT targets.

A target may retain mutable state outside the chat transcript, including:

- server-side memory,
- RAG/index or cache mutations,
- files and repository state,
- agent workspace changes,
- tool/service state,
- application/session state not represented by the adapter conversation field.

If one arm changes such state and the second arm observes it, the experiment no longer
identifies conversational-context uplift. Execution order becomes a hidden treatment.

## Decision

Every sequence-context arm and replicate SHALL execute in an independently isolated
mutable target state domain while preserving the same target identity/configuration.

`run_sequence_context_pair()` therefore requires a `TargetFixtureFactory`. Before any
arm executes, the factory is invoked for both arms and the framework verifies:

1. different target adapter objects,
2. different target isolation IDs,
3. the same declared isolation mode,
4. identical `TargetIdentity` values.

Every persisted/returned sequence observation records:

- target configuration hash,
- target isolation ID,
- target isolation mode.

The comparison summarizer also rejects reuse of an isolation ID across any arm or
replicate in the supplied comparison set.

## Isolation modes

Initial explicit modes are:

- `FRESH_ISOLATED_INSTANCE` — a new independently isolated target state domain,
- `SNAPSHOT_RESTORE` — target state restored from the same clean snapshot before use,
- `DISPOSABLE_WORKSPACE` — a separate disposable workspace, especially for agents.

The mode is provenance. It does not replace the operator/adapter responsibility to
actually provide the claimed isolation.

For AGENT tests, `DISPOSABLE_WORKSPACE` is preferred where filesystem/repository/tool
state can change. A fresh Python adapter object pointing at the same mutable external
workspace is not sufficient isolation.

## Execution order

Paired execution order remains explicit and should be counterbalanced across
case/replicate pairs. Isolation removes state carry-over; counterbalancing still helps
reduce time/runtime/cache-order effects that cannot be eliminated completely.

## Consequences

Positive:

- the context-retention intervention is better identified,
- retained and reset arms cannot silently share mutable local target state,
- AGENT/RAG experiments gain explicit workspace/state provenance,
- cross-replicate state reuse is detectable,
- paired statistics are less likely to quantify an uncontrolled order effect.

Trade-off:

- callers must provision/reset two target fixtures per pair,
- stateful remote systems need explicit snapshot/reset or disposable-environment support,
- some target adapters may initially support only exploratory sequence controls until
  reliable isolation can be demonstrated.

## Standards and evaluation alignment

This decision follows the project's fail-closed measurement philosophy and the broader
TEVV principle that the evaluation environment must match the intended measurement
concept. It also aligns with contamination-aware agent evaluation practice: scoring or
subsequent trials must not inherit mutable state that gives one arm information or
capabilities unavailable under the declared experiment.

## Architectural alignment

The change strengthens reproducibility, evidence quality and sandbox isolation without
changing the target abstraction, the `MODEL_COMPROMISE` / `SYSTEM_COMPROMISE`
distinction, or the rule that one bounded multi-turn conversation is one Blue security
trial.
