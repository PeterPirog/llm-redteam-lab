# ADR-026 — Branch-aware multi-turn Red learning and bounded portfolio planning

- Status: Proposed
- Date: 2026-09-10

## Context

A multi-turn jailbreak is a sequence-level experiment. Once Red can backtrack and create sibling branches, chronological execution order is no longer the same thing as the logical conversation path seen by Blue.

Example:

```text
A -> B
\
 -> C
```

If Red executes `A`, then `B`, then backtracks to `A` and executes `C`, the chronological log is `A, B, C`, but Blue never observed the logical transition `B -> C` on the branch containing `C`.

Treating chronology as lineage creates two measurement errors:

1. false transition learning (`B -> C` is counted even though it never occurred),
2. false success credit (an abandoned mechanism on branch `B` can be rewarded because sibling branch `C` later succeeds).

The existing `MechanismPolicy` is intentionally simple and useful as a stable baseline. Current 2026 multi-turn jailbreak research also indicates that budgets, judges, retry rules and flow control are major confounders, so any more sophisticated Red policy must be evaluated under controlled matched conditions rather than assumed superior.

## Decision

### 1. Separate execution chronology from logical lineage

The framework keeps chronological turns as the authoritative record of cost:

- target interactions,
- wall-clock/inference cost,
- actual ordinal to first violation.

Parent/child lineage is authoritative for:

- transition learning,
- sequence learning,
- branch-specific context,
- success credit.

A sibling-branch transition is never inferred from adjacent chronological turns.

### 2. Make mechanism credit branch-aware

For mechanism memory:

- every actually attempted mechanism contributes to exploration/trial accounting,
- only mechanisms on the successful logical path receive success credit,
- every real parent->child branch edge contributes a transition trial,
- only transitions on the successful logical path receive transition-success credit,
- post-success turns do not create additional causal credit for the first violation.

Malformed, cyclic or unresolved lineage fails closed instead of producing fabricated sequence evidence.

### 3. Keep abandoned branch text out of active-path prompt context

The advanced mechanism-aware Red planner receives:

- bounded content from the current active logical path,
- structural/outcome summaries for abandoned sibling branches,
- no raw target-response content from abandoned sibling branches.

This preserves useful search evidence while reducing accidental context mixing and prompt-injection carryover from a branch that is no longer active.

Target responses remain explicitly labeled `UNTRUSTED_TARGET_EVIDENCE`.

### 4. Add an experimental risk-aware mechanism portfolio policy

`RiskAwarePortfolioPolicy` is a deterministic high-level scheduler. It does not generate attack text and makes no additional model calls.

For each allowed mechanism it combines:

- a smoothed mechanism success estimate,
- a branch-aware previous-mechanism -> candidate transition estimate,
- an uncertainty/exploration bonus,
- a repeat penalty,
- a stagnation penalty,
- remaining turn-budget pressure.

Exploration pressure decreases as the authorized interaction budget is consumed. A materially better alternative may justify an earlier branch when replay/backtrack budget allows. The final turn remains reserved for an objective-focused probe rather than open-ended portfolio exploration.

The score is a Red search-control quantity, not a Blue vulnerability probability.

### 5. Preserve the simple policy as the experimental control

`MechanismPolicy` remains supported and stable as the baseline.

`RiskAwarePortfolioPolicy` is not promoted as the default merely because its deterministic tests pass. Adoption requires a paired held-out Red-component ablation with matched:

- Blue target snapshot,
- evaluation manifest,
- Judge fingerprint,
- conversation and inference budgets,
- session semantics,
- metric contract,
- stochastic seed where supported,
- counterbalanced execution order.

Effectiveness and cost remain separate outputs.

### 6. Fingerprint policy parameters

The attack-policy descriptor records the concrete scheduler type and parameters. This prevents results produced by materially different mechanism-selection rules from being silently treated as directly comparable.

## Consequences

Positive:

- sequence learning represents actual Blue conversational state,
- backtracking no longer contaminates transition statistics,
- successful sibling branches cannot retroactively reward abandoned branches,
- active-path planning has cleaner context boundaries,
- the stronger scheduler can be evaluated without changing prompt generation, Judge or budgets,
- no additional inference is required for mechanism selection.

Costs/limitations:

- branch-aware bookkeeping is more explicit,
- sparse transition evidence remains uncertain and needs repeated discovery trials,
- heuristic posterior/portfolio scoring is not claimed to be globally optimal,
- semantic "clues" still come from the configured Red planner interpreting explicitly untrusted target evidence; the deterministic scheduler does not pretend to understand raw response semantics,
- target-managed sessions cannot use replay backtracking unless the target itself provides equivalent safe branching semantics.

## Standards and research alignment

This decision is consistent with:

- NIST AI 200-2 initial public draft / TEVV-Athlon (2026), which emphasizes adaptable measurement methods for LLM, multimodal and agentic systems,
- OWASP Agent Control Standard (2026), emphasizing inspectability, traceability, instrumentability and runtime control,
- MITRE ATLAS Agentic AI techniques, which treat agent context/tool manipulation as first-class attack surfaces,
- MT-JailBench (2026), which shows that multi-turn attack rankings are confounded by budgets, evaluation functions, retries and flow-control choices and therefore motivates modular, matched component evaluation,
- RAMP (ACL 2026), which supports explicit multi-step planning and accumulation of evidence across bounded multi-turn jailbreak attempts.

## References

- NIST TEVV-Athlon: https://www.nist.gov/artificial-intelligence/ai-research/tevv-athlon-framework-evaluating-ai-systems
- OWASP Agent Control Standard: https://genai.owasp.org/resource/agent-control-standard-acs/
- MITRE ATLAS: https://atlas.mitre.org/
- MT-JailBench: https://arxiv.org/abs/2605.11002
- RAMP: https://aclanthology.org/2026.findings-acl.925/
