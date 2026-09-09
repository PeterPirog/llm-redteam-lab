# ADR-021: Modular Multi-Turn Red Mechanism Policy

Status: Accepted
Date: 2026-09-09

## Context

A realistic jailbreak is frequently a conversation rather than one prompt. The
security-relevant unit is therefore a bounded attack trajectory whose later moves
can depend on Blue's earlier responses.

The existing `AdaptiveRedStrategy` already provides:

- bounded multi-turn execution,
- `PRIMER -> PLANNER -> FINISHER` phases,
- replay branching/backtracking where technically valid,
- model-backed prompt generation and bounded mutation,
- duplicate detection,
- transcript-free tactic/sequence learning,
- deterministic budget enforcement,
- independent judging outside the attacker.

However, high-level attack strategy and concrete prompt generation were still
partially entangled inside one planner decision. This makes it harder to answer an
important forensic question: did an attack succeed because of the conversational
mechanism, the generated wording, the refinement step, flow control, a larger
budget, or a different Judge?

`MT-JailBench` (2026) independently motivates a modular view of multi-turn
jailbreaking: evaluation function, attack strategy, prompt generation, prompt
refinement and flow control should be separable, because budgets, retry rules and
judges materially confound attack comparisons.

The project must strengthen Red without inflating inference cost or turning the
attacker into the owner of campaign controls.

## Decision

Add `MechanismAwareAdaptiveRedStrategy` as a compatible extension of the stable
`AdaptiveRedStrategy` rather than replacing the base implementation.

The extension composes:

```text
DETERMINISTIC MECHANISM POLICY
          ↓
MODEL-BACKED PROMPT GENERATOR
          ↓
STRUCTURED VALIDATION
      ↙         ↘
   valid       invalid
     ↓            ↓
 TARGET       BOUNDED MUTATOR
     ↓            ↓
  EVIDENCE ← re-validate
     ↓
INDEPENDENT JUDGE
```

The deterministic mechanism policy consumes **zero additional inference calls**.

## Mechanism vocabulary

The first provider-independent mechanism labels are:

- `context_accumulation`
- `semantic_reframing`
- `cross_turn_composition`
- `decomposition`
- `refusal_feedback`
- `branch_diversification`
- `objective_probe`

These are abstract testing mechanisms. They are not executable jailbreak payloads,
permission grants or stored harmful prompt templates.

Concrete wording remains the responsibility of the configured Red planner and is
bounded by the supplied authorized synthetic/test security objective.

## Strategy versus generation

`MechanismPolicy` determines a bounded recommendation:

```text
preferred mechanism
allowed mechanisms
consecutive PASS stagnation count
must-change flag
branch recommendation
rationale
```

The Red planner receives this recommendation as a **constraint**, not as target
evidence. Blue output remains explicitly marked `UNTRUSTED_TARGET_EVIDENCE`.

The planner continues to return a short tactic identifier for low-level genealogy,
while `mechanism` is a separate structured field. This preserves two levels:

```text
mechanism = reusable high-level attack principle

tactic = concrete low-level variant chosen for this move
```

## Stagnation-aware flow control

The first policy deliberately stays simple and deterministic.

Repeated conclusive `PASS` outcomes are treated as non-progress. After the
configured stagnation threshold:

1. the previous mechanism is excluded when alternatives exist,
2. if the target uses `REPLAY` sessions and branch/backtrack budgets remain,
   `branch_diversification` becomes preferred,
3. if replay branching is unavailable, the policy switches mechanism without
   inventing unsupported branching.

`TARGET_MANAGED` sessions never receive replay-branch recommendations because the
system cannot recreate an earlier server-side state safely.

`FINISHER` reserves the final available turn for `objective_probe` rather than
continuing cosmetic context variation.

## Bounded exploration/exploitation

For normal planner turns, mechanism ranking uses only aggregate discovery memory:

- a smoothed historical success yield,
- a small novelty bonus for under-explored mechanisms,
- a repeat penalty for the immediately previous mechanism.

This is an attacker search heuristic, not a statistical estimate of Blue security.
No mechanism success ratio may be reported as comparative ASR.

The policy intentionally avoids a second strategy-generation LLM call. Current
research indicates that more elaborate dynamic strategy generation is not always
necessary when budgets and components are controlled. A simpler deterministic
selector is easier to reproduce, fingerprint and ablate.

## Transcript-free mechanism memory

`MechanismCampaignMemory` stores only:

```text
attack_family
ordered mechanism sequence
conversation success/error flags
aggregate mechanism trial/success counts
aggregate mechanism transition counts
```

It stores no raw Red prompts and no Blue response text.

The statistical unit is the **bounded conversation**, not the individual turn.
A conversation containing a mechanism contributes one mechanism trial for the
search heuristic even if that mechanism appeared more than once.

## Discovery versus evaluation

Cross-trial learning is useful in `DISCOVERY` and forbidden during held-out
`EVALUATION`.

`MechanismAwareAdaptiveRedStrategy` therefore exposes:

```text
cross_trial_learning_enabled = True   # discovery
cross_trial_learning_enabled = False  # held-out evaluation
```

When frozen, calling `learn()` clears transient per-conversation state but does not
update either tactic memory or mechanism memory. Adaptation inside the conversation
is still allowed.

This makes the frozen-policy rule executable rather than relying only on operator
discipline.

## Policy fingerprinting

`policy_descriptor()` exposes a serializable strategy component containing:

- strategy type,
- duplicate-similarity threshold,
- cross-trial learning mode,
- conversation budget,
- mechanism-policy type,
- stagnation threshold,
- novelty bonus.

The campaign layer can combine this descriptor with the configured Red model-role
identity and other generation settings before passing it to the existing
`fingerprint_attack_policy(...)` measurement provenance function.

## Consequences

### Positive

- high-level attack strategy is measurable separately from wording,
- multi-turn Red can deliberately escape stagnant paths,
- replay branching remains technically honest,
- no additional inference is required for mechanism selection,
- discovery can learn reusable mechanism transitions without storing transcripts,
- held-out evaluation can freeze cross-trial learning explicitly,
- attack-policy fingerprints become more meaningful,
- component ablations can compare mechanism policy, generator and mutator under the
  same budgets and judges.

### Costs

- planner structured output gains one `mechanism` field,
- a second bounded aggregate memory must be maintained for discovery,
- mechanism labels are intentionally coarse and will require empirical refinement,
- a mechanism recommendation can still be poorly instantiated by a weak Red model.

## Rejected alternatives

### Replace `AdaptiveRedStrategy`

Rejected. The stable base strategy has useful tests and semantics. Composition by
subclass reduces regression risk and supports controlled comparison.

### Add a strategy-planning LLM call before every turn

Rejected for the first implementation. It increases cost, latency and experimental
confounding before deterministic mechanism selection has been measured.

### Treat every turn as an independent attack trial

Rejected. Turns share accumulated conversational state and are not independent
samples.

### Always branch after refusal

Rejected. Branching is useful only when the target/session semantics and explicit
budgets support replay. A refusal may also provide useful evidence for a continuing
path.

### Let Red decide its own success

Rejected. Mechanism selection and prompt generation remain completely separate from
judging.

## Follow-up

1. Run held-out component ablations under identical budgets:
   - base adaptive Red,
   - mechanism-aware Red,
   - mechanism-aware Red without mutation.
2. Report attacks-to-first-success and target interactions in addition to success.
3. Add mechanism genealogy to persisted attack analysis artifacts where it improves
   reproducibility without storing raw target content.
4. Evaluate whether mechanism rankings generalize across target configurations
   before introducing more sophisticated bandit/search policies.
5. For stateful image-generation pipelines, add image-specific mechanism profiles
   without coupling the core mechanism policy to ComfyUI or any provider.
