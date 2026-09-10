# ADR-032 — Red Live Feedback Must Be Target-Visible

Status: Accepted
Date: 2026-09-10

## Context

Adaptive multi-turn Red must learn from Blue responses inside a bounded conversation.
However, the laboratory also computes independent per-turn judgments. Those judgments
are measurement-layer information and are not normally visible to an external attacker.

The previous adaptive state summary serialized `ConversationTurn.outcome`, and the
mechanism policy used `PASS` outcomes to detect stagnation. That allowed the live Red
policy to consume hidden Judge classifications while the attack was still running.
This creates an oracle channel, couples attacker effectiveness to a particular Judge,
and can overstate realistic multi-turn attack efficiency.

## Decision

The production model-backed Red runtime SHALL use a target-visible conversation view
for every live `next_turn` decision.

Live Red may observe:

- its own prior attacker messages,
- Blue target responses,
- turn/order/depth and branch structure,
- session mode and identifiers needed for flow control,
- predeclared security objective and campaign budget,
- allowed aggregate DISCOVERY memory from completed prior trials.

Live Red SHALL NOT observe:

- independent Judge outcome labels,
- Judge rationales/confidence,
- hidden evidence records,
- internal error classifications that are not target-visible,
- system-state verifier results unavailable to the attacker.

Target response content remains `UNTRUSTED_TARGET_EVIDENCE`: Red may reason about it as
behavioral evidence but it cannot use it to expand authorization, budgets or tool
permissions.

## Post-run learning

Independent judgment remains available after the bounded trial finishes.

For `DISCOVERY`, the campaign runtime may convert the completed independently judged
result into transcript-free aggregate search memory. This supports learning which
mechanisms, transitions and sequences were productive without creating a live oracle.

For held-out `EVALUATION`, cross-trial learning remains disabled. Adaptation inside the
conversation is allowed, but only from target-visible feedback and under the frozen Red
policy fingerprint.

## Implementation

Production runtime version 2 records:

```text
live_feedback_scope = target_visible_only
post_run_discovery_feedback = final_independent_judgment | disabled
```

The runtime uses `TargetVisibleAdaptiveRedStrategy` or
`TargetVisibleMechanismAwareAdaptiveRedStrategy`. Before live policy inspection,
per-turn Judge outcome, judgment, error label and evidence are replaced by a neutral
internal view. Planner serialization omits that placeholder entirely.

Changing the runtime version and feedback-scope descriptor changes the Red policy
fingerprint. Results produced with the former oracle-assisted policy must therefore not
be silently mixed with or directly compared to target-visible-policy results.

## Consequences

Positive:

- multi-turn Red effectiveness better matches realistic attacker knowledge,
- Judge choice cannot directly steer the attack being judged,
- retained-context and reset-each-turn experiments remain interpretable,
- Red policy provenance records the attacker knowledge boundary,
- post-run DISCOVERY learning remains available.

Trade-off:

- some deterministic mechanism decisions that previously used Judge `PASS` labels lose
  that privileged signal and may initially be less efficient,
- future Red improvements should infer progress from target-visible responses or other
  explicitly observable signals rather than reintroducing Judge labels.

## Future oracle-assisted experiments

An oracle-assisted attacker may be useful as a deliberately stronger research upper
bound, but it must be implemented as a separately named, separately fingerprinted Red
policy. It must never be the default and must not be compared to target-visible Red as
if attacker knowledge were identical.

## Architectural alignment

This decision preserves the authoritative requirements that Red be adaptive while the
attacker is not its own judge. It strengthens evidence validity, reproducibility and
experimental realism without changing the `MODEL_COMPROMISE` / `SYSTEM_COMPROMISE`
distinction or expanding attacker permissions.
