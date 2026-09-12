# ADR-050: Explicit Multi-Attacker Runtime Routing

- Status: Accepted
- Date: 2026-09-12

## Context

ADR-049 defines valid estimands for a fixed attacker pool. The execution layer previously
resolved exactly one `red_planner` and one `red_mutator` configuration per campaign.
`ModelRoleConfig.fallback` already existed, but fallback describes provider/model availability
recovery and cannot safely represent intentional attacker diversity.

Adaptive multi-round red-team research indicates that attacker diversity can reveal successful
attacks not found by the strongest individual attacker. The value comes from distinct search
behavior, so attacker identity and model configuration must be explicit, reproducible and
budgeted rather than hidden behind retry/fallback behavior.

The project also requires strict campaign inference budgets. Adding N attacker variants must
not silently multiply the authorized model-call or token budget by N.

## Decision

Add explicit multi-attacker runtime routing with these rules:

1. `ModelsConfig.red_attacker_pool` is a separate optional configuration object. An enabled
   pool requires at least two enabled, distinct variants.
2. Each variant has an explicit `id`, planner `ModelRoleConfig`, mutator `ModelRoleConfig`,
   enabled flag and stable configuration fingerprint.
3. Planner variants must advertise `text` + `reasoning`; mutator variants must advertise
   `text`. Existing local-first/cloud policy is applied to every enabled variant.
4. `fallback` remains unchanged and is never used to enumerate, select or identify attacker
   variants.
5. Variant routing is legal only for `red_planner` and `red_mutator`. Judge, forensic,
   reporter and other roles fail closed if given attacker-variant routing metadata.
6. `AttackerVariantRoleModelClient` stamps the predeclared variant ID onto every Red model
   request. A conflicting ID is an orchestration error and fails closed.
7. `BudgetedRoleModelClient` resolves the selected variant before reserving tokens, so the
   exact variant's `max_output_tokens` is accounted. Budget counters remain the logical
   `red_planner` / `red_mutator` counters.
8. `OpenAICompatibleRoleModelClient` resolves endpoint, model, temperature and token limits
   from the selected variant and records the variant ID in provider metadata.
9. `RedStrategyRuntime` accepts an optional attacker variant ID. Its immutable descriptor
   binds that ID, the variant fingerprint and exact planner/mutator descriptors.
10. `RedAttackerPoolRuntime` creates one independent `RedStrategyRuntime` per enabled variant
    but injects the **same `BudgetLedger`** into every runtime. Each attacker therefore has
    independent transcript-free search memory while consuming one campaign-wide inference
    budget.
11. DISCOVERY/EVALUATION semantics do not change. Each runtime may learn across trials only
    in DISCOVERY; held-out EVALUATION remains cross-trial frozen and cannot select a best
    attacker based on held-out outcomes.

## Measurement semantics

This routing layer does not change the unit of analysis. One bounded conversation remains one
security trial. Pool-level discovery metrics remain the distinct estimands defined in
ADR-049. Routing multiple attackers therefore cannot inflate ordinary ASR by treating the
pool as one super-trial.

The attacker's model identity is part of Red policy identity, not Blue target identity.
Changing the attacker variant must not create a different Blue security target.

## Budget semantics

All attacker variants share the same global model-call and output-token limits. The logical
role counters remain suitable for hard enforcement and historical budget compatibility.
Per-attacker model calls/tokens are diagnostic observations and may be summarized by the
attacker-pool metrics without granting separate budgets.

This is intentionally conservative: a three-attacker experiment with a campaign limit of 30
Red model calls has 30 total calls available, not 90.

## Consequences

Positive consequences:

- live Red inference can intentionally use heterogeneous attacker configurations;
- every inference is attributable to a stable attacker ID;
- attacker diversity is reproducible and independent of provider fallback behavior;
- variant-specific output limits are reserved correctly;
- pool experiments cannot silently multiply campaign budgets;
- each attacker can learn its own DISCOVERY search history without contaminating another
  attacker's internal search memory.

Trade-offs and remaining work:

- this milestone provides routing/runtime construction, not yet a complete campaign-level
  full-cross scheduler/persistence adapter;
- model names remain external configuration and must be selected locally by the operator;
- a later runner must bind the ADR-049 attacker-pool contract to persisted trial scheduling
  and finding fingerprints before reporting final multi-attacker discovery metrics;
- local OpenCode/Ollama execution still requires the independently verifiable network topology
  described by the current implementation frontier.

## References

- Adaptive Adversaries: A Multi-Turn, Multi-LLM Benchmark for LLM Agent Security:
  https://arxiv.org/abs/2607.18063
- NIST AI 800-3, Expanding the AI Evaluation Toolbox with Statistical Models:
  https://doi.org/10.6028/NIST.AI.800-3
- OWASP Agent Control Standard:
  https://genai.owasp.org/resource/agent-control-standard-acs/
