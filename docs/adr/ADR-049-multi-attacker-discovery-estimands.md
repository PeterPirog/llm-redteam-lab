# ADR-049: Multi-Attacker Discovery Estimands

- Status: Accepted
- Date: 2026-09-12

## Context

The laboratory already supports adaptive multi-turn attacks, target-visible feedback,
mechanism-aware search, branch/backtrack control and a risk-aware mechanism portfolio. That
portfolio chooses *attack mechanisms*; it does not measure the additional discovery value of
using multiple distinct attacker-model configurations.

Recent adaptive-agent red-team research reports that multi-round adaptation materially
increases attack success over first-turn-only testing and that pooling several frontier
attacker LLMs uncovers substantially more unique successful attacks than the best single
attacker. This supports attacker diversity as a discovery dimension, but it does not justify
post-hoc cherry-picking the strongest attacker and relabeling that result as ordinary ASR.

NIST AI 800-3 also emphasizes that evaluation estimands and their assumptions must be defined
explicitly. A fixed-benchmark rate and a generalized-population claim are different targets
of inference and require different uncertainty treatment. The same discipline applies to a
single-attacker trial rate versus a fixed-pool discovery opportunity.

## Decision

Introduce a deterministic `AttackerPoolContract` and attacker-pool discovery report before
wiring multiple live attacker models into campaign execution.

The contract uses these rules:

1. An attacker variant is a stable pair of planner and mutator configuration fingerprints;
   model/provider names remain runtime configuration and are not hard-coded in Red logic.
2. The pool, case IDs, replicate count, target snapshot, budget fingerprint, scope manifest
   and metric-definition version are fixed before observations are summarized.
3. The first supported allocation is a complete full cross: every attacker variant receives
   every declared `(case_id, replicate)` opportunity.
4. Every bounded conversation remains one security trial. Ordinary per-attacker ASR, MCR and
   SCR are computed from those trials using the existing campaign metric definitions.
5. A separate `portfolio_discovery_success_rate` uses `(case_id, replicate)` as its
   denominator and asks whether at least one predeclared attacker in the fixed pool found a
   violation. It must never be relabeled as ordinary ASR.
6. If no attacker succeeds but any member of the opportunity is unresolved, the pool
   opportunity is unresolved rather than defensive success. If at least one attacker has a
   conclusive violation, the pool opportunity is a known success even when another attacker
   is unresolved.
7. Unique-vulnerability metrics require an evidence-backed `finding_fingerprint` from the
   minimization/forensics pipeline. Raw prompt hashes, paraphrases or surface-form diversity
   are not accepted as distinct vulnerabilities.
8. Reports expose per-attacker distinct findings, findings exclusive to that attacker,
   pairwise finding-set Jaccard overlap and findings per model-call budget. These are Red
   discovery diagnostics, not Blue-security estimands.
9. The report carries `comparable_blue_estimate = false` so attacker search diversity cannot
   be mistaken for a comparable Blue vulnerability estimate.

## Discovery versus held-out evaluation

Multi-attacker discovery may use several attacker configurations to broaden search, but live
Judge verdicts remain unavailable to attackers. Cross-trial learning remains governed by the
existing rule: enabled only in `DISCOVERY` and frozen in held-out `EVALUATION`.

A future live attacker-pool runner may be used in held-out evaluation only when the pool,
allocation, budgets and model configuration fingerprints are predeclared and frozen. It may
not select the best attacker after observing held-out outcomes.

The existing `ModelRoleConfig.fallback` is **not** reinterpreted as an attacker ensemble.
Fallback is an availability/recovery concept. Intentional attacker diversity requires an
explicit pool configuration in a later milestone; conflating the two would change evaluation
semantics and target the wrong estimand.

## Consequences

Positive consequences:

- attacker diversity can be measured without corrupting ordinary ASR;
- additional discovery from a second/third attacker is visible as marginal unique findings;
- search efficiency remains budget-aware;
- unresolved observations cannot become silent Blue wins;
- the future live multi-attacker implementation has a fixed measurement contract to satisfy.

Trade-offs:

- full-cross allocation is more expensive than opportunistic routing;
- successful observations require downstream finding/minimization identity before diversity
  metrics can be finalized;
- this milestone measures a pool but does not yet route live inference among several attacker
  model configurations.

## References

- Adaptive Adversaries: A Multi-Turn, Multi-LLM Benchmark for LLM Agent Security:
  https://arxiv.org/abs/2607.18063
- NIST AI 800-3, Expanding the AI Evaluation Toolbox with Statistical Models:
  https://doi.org/10.6028/NIST.AI.800-3
- OWASP Agent Control Standard:
  https://genai.owasp.org/resource/agent-control-standard-acs/
