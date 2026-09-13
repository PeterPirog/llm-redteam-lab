# ADR-067: Learn compromise layers across discovery trials without a live Judge oracle

- Status: Proposed
- Date: 2026-09-13

## Context

Adaptive Red already learns transcript-free tactic, transition and sequence outcomes across DISCOVERY trials. Live within-conversation adaptation intentionally receives only target-visible state; independent Judge verdicts are withheld until the bounded conversation has ended so the attacker cannot use the Judge as an oracle.

The existing cross-trial memory reduces a completed trial to a binary objective-success signal. That is sufficient for ordinary model-only targets, but it loses security-layer information for agentic systems. In particular, these two outcomes are materially different for future attack planning:

1. the model follows a forbidden instruction but sandbox/authorization controls block the effect (`MODEL_COMPROMISE` only);
2. the surrounding system permits the unauthorized effect (`SYSTEM_COMPROMISE`, with or without model compromise).

Treating both as the same historical success can cause a discovery attacker to keep exploiting a model behavior that is already reliably contained instead of pivoting toward authorization, tool, persistence or system-boundary hypotheses.

## Decision

DISCOVERY runtimes use a bounded `LayerAwareRedCampaignMemory` that extends the existing transcript-free tactic/sequence memory with aggregate post-run counts for:

- any model compromise;
- any system compromise;
- contained model compromise (`model=true`, `system=false`);
- system-only compromise (`model=false`, `system=true`);
- combined model-and-system compromise.

The runtime records these booleans only after the strategy has completed its normal post-run `learn(result)` step. The compact memory summary made available to a later trial contains aggregate counts only.

The memory MUST NOT contain prompts, target responses, Judge rationale, tool payloads, system-state contents, secrets or evidence bodies.

Held-out `EVALUATION` remains cross-trial frozen. It neither calls strategy learning nor records compromise-layer memory.

The live conversation boundary is unchanged: current-trial Red never receives independent Judge outcomes through this feature.

## Policy identity

The model-backed Red policy descriptor adds:

- `post_run_learning_signal=outcome-layers-v1` for DISCOVERY and `disabled` for EVALUATION;
- `initial_learning_memory=empty-layer-aware-v2`.

Historical runtime-version integers remain unchanged (`2` generic, `3` AGENT, `4` fixture-primed, plus the existing multi-attacker increment). The new descriptor fields change the attack-policy fingerprint, so the new learning behavior cannot be confused with the previous policy while preserving the established meaning of those runtime-version numbers.

## Measurement boundary

Layer-aware memory is Red search diagnostics and attacker state. It is not a Blue security estimand and MUST NOT change ASR/MCR/SCR denominators. One bounded conversation remains one statistical trial.

A contained model compromise remains a model compromise and not a system compromise. The new memory exists to make Red search more effective at finding the latter without weakening that distinction.

## Known follow-up: successful-path credit

This ADR adds aggregate compromise-layer memory but does not redefine branch/sequence success credit inside `AdaptiveRedStrategy.learn()` or `MechanismAwareAdaptiveRedStrategy.learn()`. Those strategies currently use the first generic objective-violation turn as the successful logical-path endpoint. For an AGENT run that reaches `MODEL_COMPROMISE` and later reaches `SYSTEM_COMPROMISE`, that endpoint can stop too early and omit the later system-escalation step from successful tactic/mechanism credit.

Issue #75 tracks the required follow-up: post-run DISCOVERY credit should prefer the first confirmed system-compromise turn, then the first model-compromise turn, while preserving branch lineage and the live Judge boundary. PR #74 must not be interpreted as resolving that separate genealogy-credit issue.

## Consequences

- Red can learn that one family reliably reaches the model layer but not the system layer and can adapt later discovery trials accordingly.
- The feature improves AGENT discovery without leaking a Judge oracle into the current conversation.
- Multi-attacker variants continue to own separate learning memories, so one attacker does not receive another attacker's private search state.
- Fixed held-out evaluation remains comparable because cross-trial learning is still frozen.
- System-layer successful-path credit remains a separate, explicit high-priority task rather than a hidden limitation.
