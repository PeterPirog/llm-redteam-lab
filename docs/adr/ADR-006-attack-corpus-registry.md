# ADR-006: Provenance-Aware Attack Corpus Registry

- Status: Accepted
- Date: 2026-09-08

## Context

`llm-redteam-lab` needs a reusable starting corpus for evaluating new Blue targets before expensive adaptive Red inference is used. Public jailbreak and prompt-injection resources exist across multiple generations of research, but they differ in target type, attack mechanism, risk taxonomy, license, access restrictions, evaluation method and execution cost.

A flat directory of copied prompts would create several problems:

- stale and duplicated attacks,
- unclear provenance and licensing,
- no distinction between attack complexity and target difficulty,
- no benign controls for measuring over-refusal,
- poor coverage of coding agents and image-generation systems,
- no structured feedback from past successes and failures,
- temptation to run expensive model-driven attacks before the harness is proven.

## Decision

The project will maintain a provenance-aware Attack Corpus Registry under `corpus/`.

The registry has five conceptual layers:

1. **Sources** — upstream benchmark/dataset/project provenance and access policy.
2. **Techniques** — normalized attack mechanisms independent of harmful goals.
3. **Cases** — executable normalized test definitions.
4. **Packs** — target-class-specific staged collections with escalation policy.
5. **Evidence** — experiment results stored outside immutable corpus definitions and linked back by case/source IDs.

The four first-class target classes are:

- `writing`,
- `reasoning`,
- `coding`,
- `image_generation`.

### Complexity versus observed difficulty

Corpus cases use mechanism complexity tiers `T0` through `T5`:

- T0 controls/utility,
- T1 cheap static baseline,
- T2 composed/semantic transformations,
- T3 adaptive single-turn/multi-attempt,
- T4 multi-turn/indirect/environment-mediated,
- T5 specialized target-specific/cross-modal/optimized.

These tiers MUST NOT be interpreted as target-specific difficulty.

Observed target difficulty is derived from evidence such as attack success rate, attempts/turns to success, reproduction rate and budget exhaustion.

### External data policy

External resources are tagged as `reference`, `external`, `gated`, `vendored` or `native`.

Default is `external` rather than vendoring.

Gated data must never be obtained by bypassing upstream access controls. Mixed-license sources require record-level provenance. Real-service benchmarks require explicit user opt-in and dedicated synthetic test accounts/data.

Native cases use synthetic canaries and inert effects only.

### Cost-aware escalation

Campaigns SHOULD proceed in this order:

```text
T0 controls
 -> T1 static baseline
 -> T2 composed/semantic baseline
 -> T3 adaptive search
 -> T4 stateful/indirect/agent attacks
 -> T5 specialized target-specific exploration
```

A cost-sensitive campaign may stop after a reproducible cheap failure. A coverage campaign may continue when explicitly requested.

### Red learning

Attack success is not the only useful evidence. Known failures must also be preserved in Blue target history so adaptive Red agents can avoid repeatedly exploring unproductive branches.

## Consequences

### Positive

- reproducible baseline before adaptive inference,
- lower token/model cost,
- clearer licensing and provenance,
- target-class-specific coverage,
- direct support for attack genealogy and Blue Security Profiles,
- objective measurement of over-refusal,
- easier integration of future benchmarks without architectural coupling.

### Costs

- importer/normalization code is required,
- upstream datasets may change or disappear,
- some records cannot be redistributed,
- comprehensive runs need source-specific dependencies and access approvals.

## Non-goal

The registry is not intended to become an indiscriminate archive of harmful prompts. Its purpose is reproducible security evaluation and evidence-backed understanding of why defenses succeed or fail.
