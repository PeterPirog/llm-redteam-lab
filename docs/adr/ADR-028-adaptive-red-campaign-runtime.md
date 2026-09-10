# ADR-028: Adaptive Red campaign runtime

Status: Proposed

## Context

The repository already has adaptive, mechanism-aware and risk-aware portfolio multi-turn Red strategies, but the first persisted campaign lifecycle intentionally executes only deterministic static Red. Model-backed Red must not bypass the existing preflight, budget, target-snapshot, evidence, persistence or measurement-provenance gates.

Multi-turn attack effectiveness is highly sensitive to turn budgets, flow control, Judge configuration and cross-trial learning. A held-out EVALUATION must therefore freeze cross-trial learning while preserving bounded within-conversation adaptation.

## Decision

Introduce a provider-independent `RedStrategyRuntime` that is created inside the persisted campaign lifecycle after preflight and budget resolution.

The runtime:

- receives the campaign-selected `RedPolicyKind`, logical model configuration and an injected `RoleModelClient`;
- decorates model access with the same campaign `BudgetLedger` used for target interactions;
- creates one bounded multi-turn strategy per attack case;
- supports `adaptive`, `mechanism` and `portfolio` policies;
- shares transcript-free discovery memory across cases/trials by attack family;
- updates cross-trial memory only for `DISCOVERY`;
- freezes cross-trial memory for `EVALUATION` while allowing the strategy to react to Blue responses inside the current conversation;
- fingerprints the starting memory state, exact Red model-role configuration, conversation-flow budget and strategy parameters before the first target interaction;
- records Red sequence diagnostics separately from Blue vulnerability metrics.

`static` remains the deterministic control arm and remains available through the existing lifecycle.

## Flow-control identity

The campaign budget explicitly includes:

- maximum turns per attack,
- maximum backtracks per attack,
- maximum branches per attack.

These fields are measurement conditions, not implementation details, and therefore participate in the persisted budget fingerprint.

## Measurement semantics

One complete multi-turn conversation is one Blue statistical trial. Individual turns, model calls, backtracks and branches are Red efficiency/resource units.

Adaptive discovery yield is not comparative Blue ASR. Held-out EVALUATION requires:

- frozen cross-trial Red learning,
- pinned Blue target snapshot,
- held-out manifest,
- exact Red policy fingerprint,
- exact Judge fingerprint,
- exact budget fingerprint.

Portfolio scores and learned sequence/mechanism rates are Red search diagnostics only.

## Security

Target output remains `UNTRUSTED_TARGET_EVIDENCE`. Model-generated Red decisions cannot change target permissions, campaign budgets, network policy, git policy, Judge selection, model roles or the held-out partition. Invalid model output fails closed through existing structured-output validation.

## Consequences

The lifecycle can run realistic adaptive multi-turn campaigns without weakening measurement provenance. Red strategies become replaceable experimental components whose comparative value can be tested with the existing paired-ablation machinery.
